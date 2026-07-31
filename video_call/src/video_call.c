/* video_call.c
   Standalone console application: encrypted video+audio calls
   (FFmpeg + SDL3 + PortAudio + Opus + libsodium)
   Supports: Windows (Winsock2) and POSIX (Linux/macOS)

   Commands:
     video_call genkey
     video_call listdevices
     video_call call <ip> <port> [options] [local_port]
     video_call listen <port> [options]
     video_call hub <port>
*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <signal.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  include <windows.h>
#  include <io.h>
#  define isatty _isatty
#  define fileno _fileno
#  define THREAD_RET DWORD WINAPI
#else
#  include <unistd.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <sys/time.h>
#  include <netinet/tcp.h>
#  include <netdb.h>
#  include <pthread.h>
#  define THREAD_RET void*
#endif

/* Resolve a host (literal IPv4 or DNS name) into an IPv4 in_addr.
 * Returns 0 on success, -1 on failure. */
static int resolve_host_v4(const char *host, struct in_addr *out) {
    if (inet_pton(AF_INET, host, out) == 1) return 0;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

#include <opus.h>
#include <sodium.h>
#include <portaudio.h>
#define SDL_MAIN_HANDLED
#include <SDL3/SDL.h>

/* Reused audio modules */
#include "audio_types.h"
#include "audio_network.h"
#include "audio_ring.h"
#include "audio_codec.h"
#include "audio_crypto.h"
#include "audio_hub.h"
#include "media_keys.h"
#include "media_hello.h"
#include "media_senders.h"
#include "media_packet.h"

/* Per-call identifier from --call-id. Mandatory: every media key, every
 * sender tag and the HELLO2 MAC key are bound to it, so there is nothing
 * sensible to derive without one. */
static uint8_t g_call_id[MK_CALLID_BYTES];
static int g_have_call_id = 0;

/* K_room generation. Nothing produces a nonzero one yet and every platform
 * must agree on it, so it is fixed at 0 and announced in HELLO2. */
#define VC_KEY_VERSION 0

/* Video modules */
#include "video_types.h"
#include "video_capture.h"
#include "video_codec.h"
#include "video_display.h"
#include "video_fragment.h"
#include "video_quality.h"

/* Identity */
#include "identity.h"

/* ===== Configuration ===== */

#define VC_SAMPLE_RATE       48000
#define VC_CHANNELS          1
#define VC_FRAME_MS          20
#define VC_FRAME_SAMPLES     ((VC_SAMPLE_RATE/1000)*VC_FRAME_MS)
#define VC_MAX_OPUS_BYTES    1275
#define VC_MAX_VP8_FRAME     (256 * 1024) /* 256 KB max VP8 frame */
#define VC_MAX_YUV_FRAME     (1920 * 1080 * 3 / 2) /* Max YUV420P frame */

/* Deepest a sender's jitter buffer may get before old frames are dropped.
 * A relay burst must not turn into half a second of delay that never drains. */
#define MAX_PLAYOUT_FRAMES   20

/* How many participants are rendered at once.
 *
 * The sender table holds MS_MAX_SLOTS (32) because the transport does, but
 * decoding 32 streams is not something a laptop will do, and a room where
 * eight people talk at once is unusable for human reasons long before that.
 * Senders past these limits are still authenticated and still tracked - they
 * are simply not rendered, and the one heard longest ago gives up its decoder
 * when somebody new arrives. Its key and replay window stay in the sender
 * table, so it comes back the moment it speaks again.
 *
 * Video is a quarter of audio deliberately: a VP8 decoder costs orders of
 * magnitude more than an Opus one, and four pictures already fill a window. */
#define VC_MAX_MIX     8
#define VC_MAX_VIDEO   4

/* A participant silent this long gives its cell back rather than leaving a
 * frozen face in the grid. Generous, because it also covers the gap while a
 * sender's next keyframe is on its way. */
#define VC_TILE_STALE_MS  3000

/* An RTT above this cannot be a round trip on any network we serve, so it is
 * somebody else's clock arriving in the echo. See where it is used. */
#define VC_RTT_SANE_MAX_MS 5000

/* AES-GCM constants */
#define AES_GCM_KEY_LEN   crypto_aead_aes256gcm_KEYBYTES
#define AES_GCM_NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define AES_GCM_ABYTES    crypto_aead_aes256gcm_ABYTES

/* Replay protection now lives in media_senders.h: one sliding window per
 * (sender, counter domain), fed only by ms_accept_seq and only after the AEAD
 * tag has verified. The single global window this file used to keep could not
 * survive a second sender, and it accepted arbitrarily large forward jumps. */

/* ===== VideoCall state ===== */

/**
 * One rendered participant on the audio path: its Opus decoder, its jitter
 * buffer, and enough bookkeeping to decide who gives up a decoder when a new
 * voice arrives. Mirrors MixSlot in audio_call.c deliberately - the two files
 * have the same defect and should keep the same fix.
 */
typedef struct {
    int          slot;       /**< sender-table slot, or -1 when free */
    OpusDecoder *dec;
    PcmRing      ring;
    uint64_t     last_ms;    /**< when we last decoded a frame from it */
    int          prefilled;  /**< jitter buffer has reached the play-out depth */
    uint64_t     frames;     /**< frames actually mixed, for the teardown report */
} MixSlot;

/**
 * One rendered participant on the video path.
 *
 * The reassembler is per sender because the fragment header carries only a
 * frame id, and every sender's frame ids start at 0: one shared FragReceiver
 * splices two senders' fragments into a single corrupt frame whenever their
 * ids coincide, and its last_completed_frame_id makes whichever sender is
 * numerically behind look permanently stale. The decoder is per sender for
 * the same reason the Opus decoder is - VP8 predicts from previous frames,
 * so interleaving two streams through one decoder ruins both.
 */
typedef struct {
    int           slot;      /**< sender-table slot, or -1 when free */
    VideoDecoder *dec;
    FragReceiver  frag;
    uint64_t      last_ms;   /**< last fragment accepted from it */
    uint64_t      frames;    /**< pictures decoded, for the teardown report */
    uint64_t      shown;     /**< ...of which reached the window */

    /* This participant's latest picture, its own rather than shared: the
     * window shows everyone at once, so there is no single current frame.
     * Written by the receive thread and read by the display thread, both
     * under disp_lock. */
    uint8_t      *yuv;
    size_t        yuv_cap;
    int           w;
    int           h;
    uint64_t      pic_ms;    /**< when that picture was decoded */
    char          label[8];  /**< sender tag, captioned in the cell */
} VidSlot;

typedef struct VideoCall {
    socket_t sock;
    struct sockaddr_in peer;
    int peer_set;

    /* Shared call key (K_call) and our own send context. Every field here is
     * drawn or derived once, before any thread starts, and is immutable for
     * the life of the call: that is what lets the counters run without a lock. */
    uint8_t master_key[AES_GCM_KEY_LEN];
    uint8_t call_id[MK_CALLID_BYTES];
    uint8_t hello_key[MK_KEY_BYTES];
    uint8_t own_salt[MK_SALT_BYTES];
    uint8_t own_sid[MK_SID_BYTES];
    uint8_t own_idbind[MK_IDBIND_BYTES];
    /** Our send keys, indexed by counter domain (mk_stream_t). */
    uint8_t send_key[MS_STREAMS][MK_KEY_BYTES];

    /* Receive side: one key slot and one replay window per sender. Installed
     * and read only by the receive thread (ms_init runs before any thread
     * starts), so the table itself needs no lock. */
    ms_table_t senders;
    /** Senders installed so far; the announce loop on the main thread reads it. */
    atomic_int peers_known;
    /** One line about a pre-group peer, not one line per packet. */
    int legacy_warned;
    /** Likewise for a table that cannot take another sender. */
    int install_warned;
    /** Likewise for a VP8 decoder that cannot be created. */
    int vid_warned;

    /* Packets successfully decrypted from each slot, per media type. Only the
     * teardown report reads these, and that report is what tells "installed a
     * peer" apart from "actually heard and rendered that peer" - the two look
     * identical from inside a call whose keys all agree. */
    uint64_t rx_audio[MS_MAX_SLOTS];
    uint64_t rx_video[MS_MAX_SLOTS];

    /* Transmit counters, one per counter domain. Audio packets use the audio
     * counter; video fragments AND stats share the video counter, which is
     * exactly why they must also share the video key (see media_keys.h). */
    atomic_uint_fast64_t audio_seq_tx;
    atomic_uint_fast64_t video_seq_tx;

    /* Audio */
    PaStream *in_stream;
    PaStream *out_stream;
    OpusEncoder *enc;

    /* One decoder and one jitter buffer per rendered participant, created
     * when a voice is first heard rather than up front.
     *
     * A single decoder cannot serve several senders: Opus carries state
     * across frames, so interleaving two streams through one decoder makes
     * both unintelligible - and a single output ring would have them
     * overwrite each other rather than mix. That is why per-sender keys are
     * only half of a working group call; this is the other half. */
    MixSlot mix[VC_MAX_MIX];
    int mix_ready;   /**< rings and lock exist; teardown is a no-op without it */
#ifdef _WIN32
    CRITICAL_SECTION mix_lock;
#else
    pthread_mutex_t mix_lock;
#endif

    /* Video */
    VideoCapture *capture;
    VideoEncoder *v_enc;
    VideoDisplay *display;
    QualityController quality;

    /* One VP8 decoder and one reassembler per rendered participant. Touched
     * only by the receive thread, so no lock: the display side reads the
     * single YUV buffer below, under disp_lock, exactly as before. */
    VidSlot vid[VC_MAX_VIDEO];

    /* Configuration */
    int video_enabled;
    int audio_enabled;
    int capture_width;
    int capture_height;
    int capture_fps;
    char camera_device[256];

    /* Peer video params (from HELLO) */
    int peer_video_enabled;
    int peer_width;
    int peer_height;
    int peer_fps;

    /* Peer connection tracking */
    atomic_uint_fast64_t last_recv_time;   /* ms timestamp of last data packet */
    atomic_int peer_connected;             /* 1 = receiving data, 0 = timed out */

    /* RTT measurement (ping/pong via stats packets) */
    uint32_t last_peer_ping_ts;            /* peer's timestamp to echo back */
    uint64_t peer_ping_recv_time;          /* when we received the peer's ping */
    uint32_t measured_rtt_ms;              /* our measured round-trip time */

    /* Identity signing (optional) */
    int has_identity;
    uint8_t identity_pk[IDENTITY_PK_BYTES];
    uint8_t identity_sk[IDENTITY_SK_BYTES];
    uint8_t peer_identity_pk[IDENTITY_PK_BYTES];
    int peer_verified;           /* 0=unknown, 1=verified, -1=conflict */
    char known_keys_path[512];

    /* Relay mode */
    int relay_mode;
    char relay_room[256];
    char relay_name[256];
    socket_t tcp_sock;      /* TCP socket for relay (0 = unused) */
#ifdef _WIN32
    CRITICAL_SECTION tcp_send_lock;
#else
    pthread_mutex_t tcp_send_lock;
#endif

    /* Threads */
#ifdef _WIN32
    HANDLE th_vsend;
    HANDLE th_asend;
    HANDLE th_recv;
    HANDLE th_play;
    HANDLE th_disp;
#else
    pthread_t th_vsend;
    pthread_t th_asend;
    pthread_t th_recv;
    pthread_t th_play;
    pthread_t th_disp;
#endif
    atomic_int running;
    atomic_int display_ready;

    /* Shared frame buffer for display thread */
    /* Geometry of the most recent picture from anyone, kept only so the
     * peer-timeout path can size its black frame. */
    int disp_width;
    int disp_height;
    atomic_int disp_new_frame;

    /* Local camera preview (PiP) */
    uint8_t *local_yuv;
    int local_width;
    int local_height;
#ifdef _WIN32
    CRITICAL_SECTION disp_lock;
#else
    pthread_mutex_t disp_lock;
#endif
} VideoCall;

/* ===== UDP relay registration ===== */

static int send_udp_registration(VideoCall *vc) {
    /* Packet: [0xFE][2 room_len LE][room][2 name_len LE][name] */
    uint16_t room_len = (uint16_t)strlen(vc->relay_room);
    uint16_t name_len = (uint16_t)strlen(vc->relay_name);
    size_t pkt_len = 1 + 2 + room_len + 2 + name_len;
    uint8_t pkt[1 + 2 + 256 + 2 + 256];

    pkt[0] = 0xFE;
    pkt[1] = (uint8_t)(room_len & 0xFF);
    pkt[2] = (uint8_t)((room_len >> 8) & 0xFF);
    memcpy(pkt + 3, vc->relay_room, room_len);
    pkt[3 + room_len] = (uint8_t)(name_len & 0xFF);
    pkt[3 + room_len + 1] = (uint8_t)((name_len >> 8) & 0xFF);
    memcpy(pkt + 3 + room_len + 2, vc->relay_name, name_len);

    int r = sendto(vc->sock, (const char *)pkt, (int)pkt_len, 0,
                   (struct sockaddr *)&vc->peer, sizeof(vc->peer));
    return (r == (int)pkt_len) ? 0 : -1;
}

/* ===== TCP relay helpers ===== */

#define MSG_TYPE_MEDIA_RELAY 17
#define TCP_NONCE_LEN 12

static int tcp_send_all(socket_t fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, (const char *)(p + sent), (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int tcp_recv_all(socket_t fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        int n = recv(fd, (char *)(p + got), (int)(len - got), 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int tcp_relay_connect(VideoCall *vc, const char *ip, uint16_t port) {
    vc->tcp_sock = (socket_t)socket(AF_INET, SOCK_STREAM, 0);
    if (vc->tcp_sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "TCP socket() failed\n");
        return -1;
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if (resolve_host_v4(ip, &srv.sin_addr) != 0) {
        fprintf(stderr, "TCP relay: cannot resolve host %s\n", ip);
        CLOSESOCK(vc->tcp_sock); vc->tcp_sock = 0;
        return -1;
    }
    if (connect(vc->tcp_sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        fprintf(stderr, "TCP connect failed to %s:%u\n", ip, port);
        CLOSESOCK(vc->tcp_sock); vc->tcp_sock = 0;
        return -1;
    }
    /* Disable Nagle's algorithm for low-latency media relay */
    int flag = 1;
    setsockopt(vc->tcp_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
    printf("TCP relay connected to %s:%u\n", ip, port);
    return 0;
}

static int tcp_relay_register(VideoCall *vc) {
    /* Send first message to register room+name with server */
    uint16_t room_len = (uint16_t)strlen(vc->relay_room);
    uint16_t name_len = (uint16_t)strlen(vc->relay_name);
    size_t frame_len = 2 + room_len + 2 + name_len + 2 + TCP_NONCE_LEN + 1 + 4 + 1;
    uint8_t *frame = (uint8_t *)calloc(1, frame_len);
    if (!frame) return -1;

    uint8_t *w = frame;
    w[0] = room_len & 0xFF; w[1] = (room_len >> 8) & 0xFF; w += 2;
    memcpy(w, vc->relay_room, room_len); w += room_len;
    w[0] = name_len & 0xFF; w[1] = (name_len >> 8) & 0xFF; w += 2;
    memcpy(w, vc->relay_name, name_len); w += name_len;
    w[0] = TCP_NONCE_LEN; w[1] = 0; w += 2;
    memset(w, 0, TCP_NONCE_LEN); w += TCP_NONCE_LEN;
    *w++ = MSG_TYPE_MEDIA_RELAY; /* media relay registration */
    w[0] = 1; w[1] = 0; w[2] = 0; w[3] = 0; w += 4; /* clen=1 */
    *w++ = 0; /* dummy byte */

    int ret = tcp_send_all(vc->tcp_sock, frame, frame_len);
    free(frame);
    if (ret == 0) printf("TCP relay registered: room=%s name=%s\n",
                         vc->relay_room, vc->relay_name);
    return ret;
}

static int tcp_relay_send_media(VideoCall *vc, const uint8_t *media, int media_len) {
    uint16_t room_len = (uint16_t)strlen(vc->relay_room);
    uint16_t name_len = (uint16_t)strlen(vc->relay_name);
    size_t frame_len = 2 + room_len + 2 + name_len + 2 + TCP_NONCE_LEN + 1 + 4 + (size_t)media_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) return -1;

    uint8_t *w = frame;
    w[0] = room_len & 0xFF; w[1] = (room_len >> 8) & 0xFF; w += 2;
    memcpy(w, vc->relay_room, room_len); w += room_len;
    w[0] = name_len & 0xFF; w[1] = (name_len >> 8) & 0xFF; w += 2;
    memcpy(w, vc->relay_name, name_len); w += name_len;
    w[0] = TCP_NONCE_LEN; w[1] = 0; w += 2;
    memset(w, 0, TCP_NONCE_LEN); w += TCP_NONCE_LEN;
    *w++ = MSG_TYPE_MEDIA_RELAY;
    w[0] = (uint8_t)(media_len & 0xFF);
    w[1] = (uint8_t)((media_len >> 8) & 0xFF);
    w[2] = (uint8_t)((media_len >> 16) & 0xFF);
    w[3] = (uint8_t)((media_len >> 24) & 0xFF);
    w += 4;
    memcpy(w, media, media_len);

#ifdef _WIN32
    EnterCriticalSection(&vc->tcp_send_lock);
#else
    pthread_mutex_lock(&vc->tcp_send_lock);
#endif
    int ret = tcp_send_all(vc->tcp_sock, frame, frame_len);
#ifdef _WIN32
    LeaveCriticalSection(&vc->tcp_send_lock);
#else
    pthread_mutex_unlock(&vc->tcp_send_lock);
#endif
    free(frame);
    return ret;
}

/* Read one TCP frame, return media payload size (0 = non-media skipped, -1 = error) */
static int tcp_relay_recv_media(VideoCall *vc, uint8_t *out, int out_size) {
    for (;;) {
        uint8_t hdr2[2];
        uint8_t skip[512];

        /* room_len */
        if (tcp_recv_all(vc->tcp_sock, hdr2, 2) < 0) return -1;
        uint16_t room_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (room_len > 255) return -1;
        if (tcp_recv_all(vc->tcp_sock, skip, room_len) < 0) return -1;

        /* name_len + name */
        if (tcp_recv_all(vc->tcp_sock, hdr2, 2) < 0) return -1;
        uint16_t name_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (name_len > 255) return -1;
        if (tcp_recv_all(vc->tcp_sock, skip, name_len) < 0) return -1;

        /* nonce_len + nonce */
        if (tcp_recv_all(vc->tcp_sock, hdr2, 2) < 0) return -1;
        uint16_t nonce_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (nonce_len > sizeof(skip)) return -1;
        if (nonce_len > 0 && tcp_recv_all(vc->tcp_sock, skip, nonce_len) < 0) return -1;

        /* type */
        uint8_t type;
        if (tcp_recv_all(vc->tcp_sock, &type, 1) < 0) return -1;

        /* clen */
        uint8_t clenbuf[4];
        if (tcp_recv_all(vc->tcp_sock, clenbuf, 4) < 0) return -1;
        uint32_t clen = (uint32_t)(clenbuf[0] | (clenbuf[1] << 8) |
                                    (clenbuf[2] << 16) | (clenbuf[3] << 24));

        /* Unsigned comparison. A signed cast here let clen >= 0x80000000 read as
         * negative, pass the bound check and overflow `out` with data from an
         * untrusted relay server (no room key required). */
        if (type == MSG_TYPE_MEDIA_RELAY && clen > 0 &&
            out_size > 0 && clen <= (uint32_t)out_size) {
            if (tcp_recv_all(vc->tcp_sock, out, clen) < 0) return -1;
            return (int)clen;
        }

        /* Skip non-media or oversized payload */
        uint32_t remaining = clen;
        while (remaining > 0) {
            uint32_t chunk = remaining > sizeof(skip) ? sizeof(skip) : remaining;
            if (tcp_recv_all(vc->tcp_sock, skip, chunk) < 0) return -1;
            remaining -= chunk;
        }
        /* Loop to read next frame */
    }
}

/* Unified send: TCP relay or UDP */
static int vc_send_packet(VideoCall *vc, const uint8_t *data, int len) {
    if (vc->relay_mode && vc->tcp_sock) {
        return tcp_relay_send_media(vc, data, len);
    }
    if (vc->peer_set) {
        int r = sendto(vc->sock, (const char *)data, len, 0,
                       (struct sockaddr *)&vc->peer, sizeof(vc->peer));
        return (r > 0) ? 0 : -1;
    }
    return -1;
}

/* ===== Key derivation =====
 *
 * One key per sender per counter domain, derived from K_call plus what that
 * sender announces. Nothing is negotiated, so a participant joining or leaving
 * changes nobody else's keys. The old crypto_kdf_derive_from_key pair - and
 * with it the KDF_CONTEXT_* / KDF_SUBKEY_* constants in video_types.h - is
 * dead: it produced one key per call that both peers shared, separated only by
 * a 4-byte nonce prefix while both started their counters at 0.
 */

static int vc_setup_media_keys(VideoCall *vc) {
    /* Our identity binding: our own Ed25519 public key when an identity is
     * loaded, 32 zero bytes when the call runs unsigned. */
    if (vc->has_identity) {
        memcpy(vc->own_idbind, vc->identity_pk, MK_IDBIND_BYTES);
    } else {
        memset(vc->own_idbind, 0, MK_IDBIND_BYTES);
    }

    /* Drawn once per call object, before any thread starts, never re-drawn. */
    randombytes_buf(vc->own_salt, MK_SALT_BYTES);

    if (mk_hello_key(vc->master_key, vc->call_id, vc->hello_key) != 0) {
        fprintf(stderr, "Failed to derive the HELLO key\n");
        return -1;
    }
    if (mk_sender_id(vc->master_key, vc->call_id, vc->own_salt,
                     vc->own_idbind, vc->own_sid) != 0) {
        fprintf(stderr, "Failed to derive our sender id\n");
        return -1;
    }
    if (mk_derive_sender(vc->master_key, MK_STREAM_AUDIO, VC_KEY_VERSION,
                         vc->call_id, vc->own_salt, vc->own_idbind,
                         vc->send_key[MK_STREAM_AUDIO]) != 0 ||
        mk_derive_sender(vc->master_key, MK_STREAM_VIDEO, VC_KEY_VERSION,
                         vc->call_id, vc->own_salt, vc->own_idbind,
                         vc->send_key[MK_STREAM_VIDEO]) != 0) {
        fprintf(stderr, "Failed to derive our media keys\n");
        return -1;
    }
    /* Passing our own salt lets the table refuse it when a relay echoes our
     * own HELLO back at us, which would install a slot holding our send keys. */
    if (ms_init(&vc->senders, vc->master_key, vc->call_id, vc->own_salt) != MS_OK) {
        fprintf(stderr, "Failed to initialise the sender table\n");
        return -1;
    }
    return 0;
}

/* ===== HELLO2 handshake ===== */

/**
 * Announce ourselves: the call we are in, the K_room generation, our own salt
 * and, when we have one, our identity. A receiver needs nothing else to derive
 * our keys, so this is the whole handshake.
 *
 * The buffer used to be sized HELLO_SIZE_VIDEO + pk + sig = 107 bytes, which a
 * signed HELLO2 (MH_SIZE_SIGNED = 158) would have smashed on every send.
 */
static int send_hello(VideoCall *vc) {
    mh_hello_t h;
    memset(&h, 0, sizeof h);

    /* Flags say what this binary sends, not what it can display. */
    if (vc->video_enabled) h.flags |= MH_FLAG_VIDEO;
    if (vc->audio_enabled) h.flags |= MH_FLAG_AUDIO;
    if (vc->has_identity)  h.flags |= MH_FLAG_IDENTITY;

    h.key_version = VC_KEY_VERSION;
    memcpy(h.call_id, vc->call_id, MK_CALLID_BYTES);
    memcpy(h.sender_salt, vc->own_salt, MK_SALT_BYTES);

    /* Video parameters are meaningful only with the flag; mh_build zeroes them
     * otherwise, so a receiver never dispatches on length. */
    if (h.flags & MH_FLAG_VIDEO) {
        const VideoQualityPreset *preset = quality_get_preset(&vc->quality);
        h.width  = (uint16_t)preset->width;
        h.height = (uint16_t)preset->height;
        h.fps    = (uint8_t)preset->fps;
    }

    uint8_t pkt[MH_SIZE_SIGNED];
    size_t pkt_len = 0;
    mh_status_t st = mh_build(&h, vc->hello_key,
                              vc->has_identity ? vc->identity_sk : NULL,
                              pkt, sizeof pkt, &pkt_len);
    if (st != MH_OK) {
        fprintf(stderr, "HELLO2 build failed: %s\n", mh_strerror(st));
        return -1;
    }

    return vc_send_packet(vc, pkt, (int)pkt_len);
}

/**
 * Handle an arriving HELLO. A packet that does not verify installs nothing,
 * resets nothing and is never answered: the old code replied to anything that
 * was merely long enough, which told an off-path prober it had found a live
 * call without ever holding the room key.
 */
static void handle_hello(VideoCall *vc, const uint8_t *buf, size_t len) {
    mh_hello_t h;
    mh_status_t st = mh_parse(buf, len, vc->hello_key, &h);
    if (st != MH_OK) {
        if (st == MH_ERR_LEGACY_PEER && !vc->legacy_warned) {
            vc->legacy_warned = 1;
            printf("Peer speaks the pre-group HELLO and cannot join this call.\n"
                   "It must be updated to a build with group-call support.\n");
            fflush(stdout);
        }
        return;
    }

    /* Redundant with the MAC, whose key is derived from call_id, but it costs
     * nothing and makes the binding explicit. */
    if (memcmp(h.call_id, vc->call_id, MK_CALLID_BYTES) != 0) return;

    uint8_t idbind[MK_IDBIND_BYTES];
    if (h.flags & MH_FLAG_IDENTITY) {
        memcpy(idbind, h.pk, MK_IDBIND_BYTES);
    } else {
        memset(idbind, 0, sizeof idbind);
    }

    /* ms_install is idempotent per salt, so a repeated HELLO installs nothing
     * and, crucially, resets no replay window. Comparing the slot count is how
     * we tell a genuinely new participant from a retransmission. */
    int before = ms_count(&vc->senders);
    int idx = -1;
    ms_status_t ins = ms_install(&vc->senders, h.sender_salt, idbind,
                                 h.key_version, &idx);
    (void)idx;
    if (ins != MS_OK) {
        /* MS_ERR_SELF is our own announcement coming back off the relay, and
         * a full or SID-capped table is a standing condition, so neither is
         * worth a line per arriving packet. */
        if (ins != MS_ERR_SELF && !vc->install_warned) {
            vc->install_warned = 1;
            fprintf(stderr, "HELLO2: sender not installed (status %d)\n", (int)ins);
        }
        return;
    }
    int is_new = (ms_count(&vc->senders) > before);

    atomic_store(&vc->last_recv_time, video_time_ms());
    atomic_store(&vc->peer_connected, 1);

    /* Peer media parameters are display information, not replay state, so they
     * follow every verified announcement. Log only when they change. */
    int new_video = (h.flags & MH_FLAG_VIDEO) ? 1 : 0;
    if (new_video != vc->peer_video_enabled || (int)h.width != vc->peer_width ||
        (int)h.height != vc->peer_height || (int)h.fps != vc->peer_fps) {
        if (new_video) {
            printf("Peer video: %ux%u @ %u fps\n",
                   (unsigned)h.width, (unsigned)h.height, (unsigned)h.fps);
        } else {
            printf("Peer is audio-only\n");
        }
        fflush(stdout);
    }
    vc->peer_video_enabled = new_video;
    vc->peer_width  = (int)h.width;
    vc->peer_height = (int)h.height;
    vc->peer_fps    = (int)h.fps;

    if (!is_new) return;

    atomic_fetch_add(&vc->peers_known, 1);

    if (h.flags & MH_FLAG_IDENTITY) {
        /* mh_parse already verified the signature, so this only decides trust.
         * TOFU is keyed by the peer's own public key: a call has many
         * participants now, and one shared "peer" entry would make every new
         * participant look like a key change. */
        char fp[IDENTITY_FINGERPRINT_LEN];
        identity_pk_fingerprint(h.pk, fp);
        tofu_result_t tofu = identity_tofu_check(vc->known_keys_path, fp, h.pk);
        memcpy(vc->peer_identity_pk, h.pk, IDENTITY_PK_BYTES);
        if (tofu == TOFU_NEW_KEY) {
            printf("[TOFU] New peer identity: %s\n", fp);
            vc->peer_verified = 1;
        } else if (tofu == TOFU_KEY_MATCH) {
            printf("[VERIFIED] Peer identity: %s\n", fp);
            vc->peer_verified = 1;
        } else {
            printf("[WARNING] PEER KEY CHANGED! Fingerprint: %s\n", fp);
            vc->peer_verified = -1;
        }
        fflush(stdout);
    } else {
        printf("Peer joined without an identity (unsigned)\n");
        fflush(stdout);
    }

    /* Nothing global is reset here any more. A peer that restarts draws a
     * fresh salt and arrives as a new sender, and reassembly and decoding are
     * now per sender, so its leftovers sit in its own retired slot and are
     * cleared when that slot is reassigned. The old global reset wiped every
     * other participant's half-assembled frame and reference frames as well,
     * which in a group call means one person rejoining freezes everybody
     * else's picture until their next keyframe. */

    /* One reply, so the new participant learns our salt without waiting for
     * the next beacon. Repetition really is the announce loop's job now: it
     * keeps running for the life of the call, so a dropped reply costs the
     * newcomer a beacon interval instead of the whole call. */
    if (vc->peer_set || vc->tcp_sock) send_hello(vc);
}

/* ===== Encryption helpers =====
 *
 * Send: mp_encrypt with our own SID, our own key for that counter domain, and
 * the existing per-stream transmit counter. The counter may still start at 0,
 * which is safe now only because the key is ours alone.
 *
 * Receive: the SID in the header picks the key, so there is no "the peer" any
 * more and nothing caches a nonce prefix.
 */

static int encrypt_audio_pkt(VideoCall *vc, const uint8_t *opus, size_t opus_len,
                              uint8_t *out, size_t out_cap, size_t *out_len,
                              uint64_t counter) {
    return mp_encrypt(PKT_TYPE_AUDIO, vc->own_sid, counter,
                      vc->send_key[MK_STREAM_AUDIO],
                      opus, opus_len, out, out_cap, out_len);
}

static int encrypt_video_frag(VideoCall *vc, const uint8_t *frag, size_t frag_len,
                               uint8_t *out, size_t out_cap, size_t *out_len,
                               uint64_t counter) {
    return mp_encrypt(PKT_TYPE_VIDEO_FRAG, vc->own_sid, counter,
                      vc->send_key[MK_STREAM_VIDEO],
                      frag, frag_len, out, out_cap, out_len);
}

static int encrypt_stats(VideoCall *vc, const StatsPayload *stats,
                          uint8_t *out, size_t out_cap, size_t *out_len,
                          uint64_t counter) {
    /* Stats are drawn from the video transmit counter (see th_vsend_func), so
     * they must use the video key: two counter domains under one key would
     * repeat a nonce, one packet type per domain never does. */
    return mp_encrypt(PKT_TYPE_STATS, vc->own_sid, counter,
                      vc->send_key[MK_STREAM_VIDEO],
                      (const uint8_t *)stats, sizeof(StatsPayload),
                      out, out_cap, out_len);
}

/**
 * Decrypt one arriving media packet, whoever sent it.
 *
 * Order matters and is the whole point: peek the SID, collect the slots that
 * answer to it (a 3-byte tag really does collide, so there can be two), try
 * each candidate's key for this counter domain, and only once a tag verifies
 * offer the counter to that slot's replay window. Touching the window before
 * the packet authenticates is how a single forged packet at a huge counter
 * silences a real sender for good.
 *
 * @return the slot index on success, -1 if nothing decrypted it or it was stale
 */
static int decrypt_from_sender(VideoCall *vc, const uint8_t *pkt, size_t pkt_len,
                               mk_stream_t stream,
                               uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t sid[MK_SID_BYTES];
    uint64_t counter = 0;
    if (mp_peek(pkt, pkt_len, NULL, sid, &counter) != 0) return -1;

    int cand[MS_SID_CAP];
    int ncand = ms_find_by_sid(&vc->senders, sid, cand);
    for (int i = 0; i < ncand; i++) {
        const uint8_t *key = ms_key(&vc->senders, cand[i], stream);
        if (!key) continue;
        if (mp_decrypt(pkt, pkt_len, key, out, out_cap, out_len) != 0) continue;
        if (ms_accept_seq(&vc->senders, cand[i], stream, counter) != MS_FRESH) return -1;
        return cand[i];
    }
    return -1;
}

/* ===== Rendered-participant pools =====
 *
 * Both pools follow the same shape as audio_call.c: bounded, filled on first
 * use, and reclaimed least-recently-heard-first. Nothing is evicted from the
 * sender table itself - keys and replay windows outlive a decoder, so a
 * participant that lost its decoder is back the instant it speaks again.
 */

static void mix_lock_take(VideoCall *vc) {
#ifdef _WIN32
    EnterCriticalSection(&vc->mix_lock);
#else
    pthread_mutex_lock(&vc->mix_lock);
#endif
}

static void mix_lock_drop(VideoCall *vc) {
#ifdef _WIN32
    LeaveCriticalSection(&vc->mix_lock);
#else
    pthread_mutex_unlock(&vc->mix_lock);
#endif
}

/**
 * Release every Opus decoder, jitter buffer and the lock. Safe on a half-built
 * call: the object is calloc'd, so mix_ready is what says whether any of this
 * was ever set up.
 */
static void mix_teardown(VideoCall *vc) {
    if (!vc->mix_ready) return;
    for (int i = 0; i < VC_MAX_MIX; i++) {
        if (vc->mix[i].dec) {
            opus_decoder_destroy(vc->mix[i].dec);
            vc->mix[i].dec = NULL;
        }
        pcmring_free(&vc->mix[i].ring);
        vc->mix[i].slot = -1;
    }
#ifdef _WIN32
    DeleteCriticalSection(&vc->mix_lock);
#else
    pthread_mutex_destroy(&vc->mix_lock);
#endif
    vc->mix_ready = 0;
}

/**
 * The decoder and jitter buffer for a sender, creating or reassigning one if
 * this is a voice we are not currently rendering. Call with mix_lock held.
 *
 * Reassignment resets the Opus state, which would otherwise decode the
 * previous stream's history as noise. Returns NULL only if a decoder cannot
 * be created at all.
 */
static MixSlot *mix_acquire(VideoCall *vc, int slot) {
    MixSlot *chosen = NULL;

    if (!vc->mix_ready) return NULL;
    for (int i = 0; i < VC_MAX_MIX; i++) {
        if (vc->mix[i].slot == slot) return &vc->mix[i];
    }
    for (int i = 0; i < VC_MAX_MIX; i++) {
        if (vc->mix[i].slot < 0) { chosen = &vc->mix[i]; break; }
    }
    if (!chosen) {
        chosen = &vc->mix[0];
        for (int i = 1; i < VC_MAX_MIX; i++) {
            if (vc->mix[i].last_ms < chosen->last_ms) chosen = &vc->mix[i];
        }
        int16_t discard[VC_FRAME_SAMPLES * VC_CHANNELS];
        while (pcmring_pop(&chosen->ring, discard) == 0) { }
        if (chosen->dec) opus_decoder_ctl(chosen->dec, OPUS_RESET_STATE);
    }

    if (!chosen->dec) {
        int err = 0;
        chosen->dec = opus_decoder_create(VC_SAMPLE_RATE, VC_CHANNELS, &err);
        if (!chosen->dec || err != OPUS_OK) {
            chosen->dec = NULL;
            return NULL;
        }
    }
    chosen->slot = slot;
    chosen->prefilled = 0;
    chosen->frames = 0;
    return chosen;
}

/** The three sid bytes a participant is known by in the logs. */
static void vc_sid_of(const VideoCall *vc, int slot, uint8_t out[MK_SID_BYTES]) {
    memset(out, 0, MK_SID_BYTES);
    if (slot >= 0 && slot < MS_MAX_SLOTS && vc->senders.slots[slot].used) {
        memcpy(out, vc->senders.slots[slot].sid, MK_SID_BYTES);
    }
}

/** Release every VP8 decoder and reassembler. Safe on a zeroed pool. */
static void vid_teardown(VideoCall *vc) {
    for (int i = 0; i < VC_MAX_VIDEO; i++) {
        if (vc->vid[i].dec) {
            video_decoder_close(vc->vid[i].dec);
            vc->vid[i].dec = NULL;
        }
        video_frag_receiver_free(&vc->vid[i].frag);
        vc->vid[i].slot = -1;
    }
}

/**
 * The reassembler and VP8 decoder for a sender, creating or reassigning one
 * if this is a picture we are not currently rendering. Receive thread only.
 *
 * Reassignment throws away both: half-assembled frames belong to the previous
 * stream and its frame ids, and a VP8 decoder holds reference frames that
 * would be predicted from. The cost is that a freshly assigned slot shows
 * nothing until that sender's next keyframe, which the encoder emits every
 * two seconds.
 *
 * Returns NULL only if a decoder cannot be created at all.
 */
static VidSlot *vid_acquire(VideoCall *vc, int slot) {
    VidSlot *chosen = NULL;

    for (int i = 0; i < VC_MAX_VIDEO; i++) {
        if (vc->vid[i].slot == slot) return &vc->vid[i];
    }
    for (int i = 0; i < VC_MAX_VIDEO; i++) {
        if (vc->vid[i].slot < 0) { chosen = &vc->vid[i]; break; }
    }
    if (!chosen) {
        chosen = &vc->vid[0];
        for (int i = 1; i < VC_MAX_VIDEO; i++) {
            if (vc->vid[i].last_ms < chosen->last_ms) chosen = &vc->vid[i];
        }
        video_frag_receiver_free(&chosen->frag);
        video_frag_receiver_init(&chosen->frag);
        if (chosen->dec) {
            video_decoder_close(chosen->dec);
            chosen->dec = NULL;
        }
        /* The picture belongs to the participant losing the slot, so it
         * leaves with them instead of sitting in the grid under somebody
         * else's caption. The buffer itself is kept for reuse. */
#ifdef _WIN32
        EnterCriticalSection(&vc->disp_lock);
#else
        pthread_mutex_lock(&vc->disp_lock);
#endif
        chosen->w = 0;
        chosen->h = 0;
        chosen->pic_ms = 0;
#ifdef _WIN32
        LeaveCriticalSection(&vc->disp_lock);
#else
        pthread_mutex_unlock(&vc->disp_lock);
#endif
    }

    if (!chosen->dec) {
        if (video_decoder_open(&chosen->dec) != 0 || !chosen->dec) {
            chosen->dec = NULL;
            if (!vc->vid_warned) {
                vc->vid_warned = 1;
                fprintf(stderr, "Warning: VP8 decoder unavailable; "
                                "video from this participant cannot be shown\n");
            }
            return NULL;
        }
    }
    chosen->slot = slot;
    chosen->frames = 0;
    chosen->shown = 0;
    {
        /* Resolved here, on the thread that owns the sender table, so the
         * display side never reads it. */
        uint8_t sid[MK_SID_BYTES];
        vc_sid_of(vc, slot, sid);
        snprintf(chosen->label, sizeof chosen->label, "%02x%02x%02x",
                 sid[0], sid[1], sid[2]);
    }
    return chosen;
}

/**
 * Paint every participant we are decoding, tiled, with our own camera in the
 * corner.
 *
 * This replaces an active-speaker policy that chose one participant to show.
 * That policy was a fair reading of a one-window constraint, but the
 * constraint was self-imposed: the decoders and reassemblers were already per
 * sender and only the presentation was not. Choosing between people is a
 * worse answer than showing them, and it read exactly as the defect it was -
 * "I saw either the laptop or the phone, never both".
 *
 * Rendering happens under disp_lock, as it did before: the alternative is
 * copying every participant's frame out first, which costs more than the
 * receive thread waiting out a present.
 */
static void vc_render_frame(VideoCall *vc) {
    if (!vc->display) return;

    VideoTile tiles[VD_MAX_TILES];
    int n = 0;

#ifdef _WIN32
    EnterCriticalSection(&vc->disp_lock);
#else
    pthread_mutex_lock(&vc->disp_lock);
#endif

    uint64_t now = video_time_ms();

    /* Slot order rather than arrival order, so a participant keeps its cell
     * instead of trading places with whoever decoded most recently. */
    for (int i = 0; i < VC_MAX_VIDEO && n < VD_MAX_TILES; i++) {
        VidSlot *v = &vc->vid[i];
        if (v->slot < 0 || !v->yuv || v->w <= 0 || v->h <= 0) continue;
        if (v->pic_ms && (now - v->pic_ms) > VC_TILE_STALE_MS) continue;

        tiles[n].yuv    = v->yuv;
        tiles[n].width  = v->w;
        tiles[n].height = v->h;
        tiles[n].label  = v->label;
        v->shown++;
        n++;
    }

    if (n > 0) {
        video_display_render_grid(vc->display, tiles, n,
                                  vc->local_yuv, vc->local_width,
                                  vc->local_height);
    }

#ifdef _WIN32
    LeaveCriticalSection(&vc->disp_lock);
#else
    pthread_mutex_unlock(&vc->disp_lock);
#endif
}

/* ===== Thread: Video Send ===== */

typedef struct { VideoCall *vc; } ThreadArgs;

static THREAD_RET th_vsend_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs *)arg;
    VideoCall *vc = ta->vc;
    free(ta);

    if (!vc->video_enabled || !vc->capture || !vc->v_enc) {
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    const VideoQualityPreset *preset = quality_get_preset(&vc->quality);
    int actual_w = vc->capture_width;
    int actual_h = vc->capture_height;
    int yuv_size = actual_w * actual_h * 3 / 2;
    uint8_t *yuv_buf = (uint8_t *)malloc(yuv_size);
    uint8_t *vp8_buf = (uint8_t *)malloc(VC_MAX_VP8_FRAME);
    /* Largest packet this thread builds is a full fragment. The 9-byte media
     * header replaces the old 1 + 8, so the size does not change. Stats are far
     * smaller and share the buffer. */
    uint8_t enc_buf[MP_HEADER_BYTES + FRAG_HEADER_SIZE + FRAG_MAX_PAYLOAD + MP_TAG_BYTES];
    FragList frags;

    if (!yuv_buf || !vp8_buf) {
        free(yuv_buf);
        free(vp8_buf);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    /* No handshake wait. Our send key comes from our own salt, so we can
     * encrypt from the first frame; the old spin blocked here until somebody
     * answered, which in a group call means blocking on whoever happens to
     * answer first. video_capture_read_latest below drains the camera queue,
     * so the dshow overflow the spin also guarded against cannot build up. */
    uint32_t frame_id = 0;
    int frame_interval_ms = 1000 / preset->fps;

    while (atomic_load(&vc->running)) {
        uint64_t t0 = video_time_ms();

        /* Check for quality level change */
        const VideoQualityPreset *cur = quality_get_preset(&vc->quality);
        if (cur->bitrate_kbps != preset->bitrate_kbps) {
            video_encoder_set_bitrate(vc->v_enc, cur->bitrate_kbps);
            preset = cur;
            frame_interval_ms = 1000 / preset->fps;
        }

        /* Capture latest frame (drains buffered frames to prevent dshow overflow) */
        int cap_ret = video_capture_read_latest(vc->capture, yuv_buf, yuv_size);
        if (cap_ret <= 0) {
            msleep(5);
            continue;
        }

        /* Copy local frame for PiP preview */
#ifdef _WIN32
        EnterCriticalSection(&vc->disp_lock);
#else
        pthread_mutex_lock(&vc->disp_lock);
#endif
        if (!vc->local_yuv || vc->local_width != actual_w || vc->local_height != actual_h) {
            free(vc->local_yuv);
            vc->local_yuv = (uint8_t *)malloc(yuv_size);
            vc->local_width = actual_w;
            vc->local_height = actual_h;
        }
        if (vc->local_yuv) {
            memcpy(vc->local_yuv, yuv_buf, yuv_size);
        }
#ifdef _WIN32
        LeaveCriticalSection(&vc->disp_lock);
#else
        pthread_mutex_unlock(&vc->disp_lock);
#endif

        /* Encode VP8 */
        int vp8_size = video_encoder_encode(vc->v_enc, yuv_buf, vp8_buf, VC_MAX_VP8_FRAME);
        if (vp8_size <= 0) continue;

        /* Fragment */
        int nfrags = video_fragment_split(vp8_buf, vp8_size, frame_id, &frags);
        if (nfrags <= 0) continue;

        /* Encrypt and send each fragment */
        for (int i = 0; i < nfrags; i++) {
            uint64_t seq = atomic_fetch_add(&vc->video_seq_tx, 1);
            size_t enc_len = 0;
            if (encrypt_video_frag(vc, frags.data[i], frags.sizes[i],
                                    enc_buf, sizeof enc_buf, &enc_len, seq) != 0) {
                continue;
            }

            if (vc_send_packet(vc, enc_buf, (int)enc_len) == 0) {
                quality_record_sent(&vc->quality);
            }
        }

        frame_id++;

        /* Send stats if needed */
        uint64_t now = video_time_ms();
        if (quality_should_send_stats(&vc->quality, now)) {
            StatsPayload sp;
            quality_build_stats(&vc->quality, &sp);

            /* Ping/pong for RTT measurement:
               reserved = our timestamp (ping)
               rtt_ms   = echo of peer's timestamp + hold time (pong)
               Hold time compensation: we add the time we held the ping
               so the peer can subtract it to get accurate RTT */
            sp.reserved = (uint32_t)(now & 0xFFFFFFFF);
            {
                uint32_t hold_time = (vc->peer_ping_recv_time > 0)
                    ? (uint32_t)(now - vc->peer_ping_recv_time) : 0;
                sp.rtt_ms = vc->last_peer_ping_ts + hold_time;
            }

            uint64_t seq = atomic_fetch_add(&vc->video_seq_tx, 1);
            size_t enc_len = 0;
            if (encrypt_stats(vc, &sp, enc_buf, sizeof enc_buf, &enc_len, seq) == 0) {
                vc_send_packet(vc, enc_buf, (int)enc_len);
            }

            /* Print stats to stdout for GUI */
            printf("[STATS] RTT=%u\n", vc->measured_rtt_ms);
            fflush(stdout);
        }

        /* Pace to target FPS */
        uint64_t elapsed = video_time_ms() - t0;
        if ((int)elapsed < frame_interval_ms) {
            msleep((unsigned)(frame_interval_ms - (int)elapsed));
        }
    }

    free(yuv_buf);
    free(vp8_buf);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== Thread: Audio Send ===== */

static THREAD_RET th_asend_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs *)arg;
    VideoCall *vc = ta->vc;
    free(ta);

    /* No handshake wait here either. Re-announcing moved to the main loop,
     * which repeats the HELLO2 without holding up a single encrypted packet. */
    if (!vc->audio_enabled) {
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    int16_t pcm[VC_FRAME_SAMPLES];
    uint8_t opus_buf[VC_MAX_OPUS_BYTES];
    uint8_t packet[MP_HEADER_BYTES + VC_MAX_OPUS_BYTES + MP_TAG_BYTES];

    while (atomic_load(&vc->running)) {
        if (vc->in_stream == NULL) {
            memset(pcm, 0, sizeof(pcm));
        } else {
            PaError pe = Pa_ReadStream(vc->in_stream, pcm, VC_FRAME_SAMPLES);
            if (pe == paInputOverflowed) continue;
            if (pe != paNoError) { msleep(2); continue; }
        }

        int enc_bytes = opus_encode(vc->enc, pcm, VC_FRAME_SAMPLES,
                                     opus_buf, (opus_int32)sizeof(opus_buf));
        if (enc_bytes < 0) continue;

        uint64_t seq = atomic_fetch_add(&vc->audio_seq_tx, 1);
        size_t pkt_len = 0;
        if (encrypt_audio_pkt(vc, opus_buf, (size_t)enc_bytes,
                               packet, sizeof packet, &pkt_len, seq) != 0) {
            continue;
        }

        vc_send_packet(vc, packet, (int)pkt_len);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== Thread: Audio play-out ===== */

/**
 * Mix every rendered participant into one output stream.
 *
 * This is its own thread rather than a tail of the receive loop, because with
 * several senders that loop fires several times per frame period and would
 * push the device far faster than real time. Pa_WriteStream blocks until the
 * device has room, so one frame per iteration is what paces this thread -
 * including the silent frames, which keep the device fed while nobody speaks.
 */
static THREAD_RET th_play_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs *)arg;
    VideoCall *vc = ta->vc;
    free(ta);

    if (!vc->audio_enabled || !vc->mix_ready) {
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    const size_t nsamp = VC_FRAME_SAMPLES * VC_CHANNELS;
    int32_t acc[VC_FRAME_SAMPLES * VC_CHANNELS];
    int16_t frame[VC_FRAME_SAMPLES * VC_CHANNELS];
    int16_t play[VC_FRAME_SAMPLES * VC_CHANNELS];

    while (atomic_load(&vc->running)) {
        memset(acc, 0, sizeof acc);

        mix_lock_take(vc);
        for (int i = 0; i < VC_MAX_MIX; i++) {
            MixSlot *m = &vc->mix[i];
            if (m->slot < 0) continue;

            /* Wait for a little depth before starting a voice, and go back to
             * waiting if it runs dry: playing every frame the instant it
             * arrives turns ordinary network jitter into chopped audio. */
            if (!m->prefilled) {
                if (atomic_load(&m->ring.count) < PLAYOUT_BUFFER_FRAMES) continue;
                m->prefilled = 1;
            }
            if (pcmring_pop(&m->ring, frame) != 0) {
                m->prefilled = 0;
                continue;
            }
            for (size_t k = 0; k < nsamp; k++) acc[k] += frame[k];
            m->frames++;
        }
        mix_lock_drop(vc);

        if (!vc->out_stream) {
            /* No output device: still drain at roughly real time so the jitter
             * buffers cannot grow without bound. */
            msleep(VC_FRAME_MS);
            continue;
        }

        /* Saturate rather than wrap. Wrapping turns two loud speakers into a
         * full-scale square wave, which is unpleasant in a way clipping is not. */
        for (size_t k = 0; k < nsamp; k++) {
            int32_t v = acc[k];
            if (v > 32767) v = 32767;
            else if (v < -32768) v = -32768;
            play[k] = (int16_t)v;
        }
        Pa_WriteStream(vc->out_stream, play, VC_FRAME_SAMPLES);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== Thread: Receive ===== */

static THREAD_RET th_recv_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs *)arg;
    VideoCall *vc = ta->vc;
    free(ta);

    /* Heap-allocate large buffers (stack is only 1MB on Windows) */
    uint8_t *rbuf = (uint8_t *)malloc(MAX_PACKET_SIZE);
    uint8_t *dec_buf = (uint8_t *)malloc(VC_MAX_VP8_FRAME);
    uint8_t *yuv_buf = (uint8_t *)malloc(VC_MAX_VP8_FRAME);
    uint8_t *opus_buf = (uint8_t *)malloc(VC_MAX_OPUS_BYTES);
    int16_t *pcm = (int16_t *)malloc(VC_FRAME_SAMPLES * sizeof(int16_t));
    /* Decoded picture scratch, allocated once. It used to be malloc'd and
     * freed per completed frame, which with several senders is a 3 MB
     * allocation several times per frame period. */
    uint8_t *yuv_dec = (uint8_t *)malloc(VC_MAX_YUV_FRAME);

    if (!rbuf || !dec_buf || !yuv_buf || !opus_buf || !pcm || !yuv_dec) {
        free(rbuf); free(dec_buf); free(yuv_buf); free(opus_buf); free(pcm);
        free(yuv_dec);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    while (atomic_load(&vc->running)) {
        int n;

        if (vc->relay_mode && vc->tcp_sock) {
            /* TCP relay: read media frame from server */
            n = tcp_relay_recv_media(vc, rbuf, MAX_PACKET_SIZE);
            if (n < 0) {
                fprintf(stderr, "[relay] TCP connection lost\n");
                atomic_store(&vc->running, 0);
                break;
            }
            if (n == 0) continue; /* non-media message, skip */
        } else {
            /* UDP: direct or UDP relay */
            struct sockaddr_in src;
#ifdef _WIN32
            int slen = sizeof(src);
#else
            socklen_t slen = sizeof(src);
#endif
            n = recvfrom(vc->sock, (char *)rbuf, MAX_PACKET_SIZE, 0,
                         (struct sockaddr *)&src, &slen);
            if (n <= 0) {
                if (vc->relay_mode) {
                    static long timeout_count = 0;
                    timeout_count++;
                    if (timeout_count <= 5 || timeout_count % 10 == 0) {
                        fprintf(stderr, "[relay-recv] timeout #%ld\n", timeout_count);
                    }
                } else {
                    msleep(2);
                }
                continue;
            }
            if (!vc->peer_set && !vc->relay_mode) {
                vc->peer = src;
                vc->peer_set = 1;
            }
        }

        uint8_t pkt_type = rbuf[0];

        /* HELLO handshake. Both packet types land here: mh_parse recognises
         * the pre-group 0x7F and says so, instead of it being dropped as
         * garbage and the call staying silently dead. handle_hello decides
         * whether to answer - an unverified HELLO is never answered. */
        if (pkt_type == MH_TYPE || pkt_type == MH_LEGACY_TYPE) {
            handle_hello(vc, rbuf, (size_t)n);
            continue;
        }

        /* Update last receive time for peer timeout detection */
        atomic_store(&vc->last_recv_time, video_time_ms());
        atomic_store(&vc->peer_connected, 1);

        /* Audio packet */
        if (pkt_type == PKT_TYPE_AUDIO && vc->audio_enabled) {
            size_t opus_len = 0;
            /* Picks the sender by SID and drops replays; both are inside. */
            int slot = decrypt_from_sender(vc, rbuf, (size_t)n, MK_STREAM_AUDIO,
                                           opus_buf, VC_MAX_OPUS_BYTES, &opus_len);
            if (slot < 0) continue;
            if (slot < MS_MAX_SLOTS) vc->rx_audio[slot]++;

            /* Into this sender's own decoder and its own jitter buffer. One
             * shared decoder garbles every stream through it, and one shared
             * ring has them overwrite each other instead of mixing - which is
             * how a call whose packets all decrypt can still be silent noise. */
            mix_lock_take(vc);
            MixSlot *m = mix_acquire(vc, slot);
            if (!m) { mix_lock_drop(vc); continue; }

            int dec_samples = opus_decode(m->dec, opus_buf, (opus_int32)opus_len,
                                          pcm, VC_FRAME_SAMPLES, 0);
            if (dec_samples > 0) {
                if (dec_samples < VC_FRAME_SAMPLES) {
                    memset(pcm + dec_samples * VC_CHANNELS, 0,
                           (VC_FRAME_SAMPLES - dec_samples) * VC_CHANNELS * sizeof(int16_t));
                }
                pcmring_push(&m->ring, pcm);
                m->last_ms = video_time_ms();

                /* Latency control per sender: a relay burst must not turn into
                 * half a second of delay that never drains. */
                while (atomic_load(&m->ring.count) > MAX_PLAYOUT_FRAMES) {
                    int16_t discard[VC_FRAME_SAMPLES * VC_CHANNELS];
                    pcmring_pop(&m->ring, discard);
                }
            }
            mix_lock_drop(vc);
            continue;
        }

        /* Video fragment */
        if (pkt_type == PKT_TYPE_VIDEO_FRAG && vc->video_enabled) {
            size_t frag_len = 0;
            /* Replays are dropped inside, before the reassembler ever sees the
             * fragment: a repeat there would corrupt a frame. */
            int slot = decrypt_from_sender(vc, rbuf, (size_t)n, MK_STREAM_VIDEO,
                                           dec_buf, VC_MAX_VP8_FRAME, &frag_len);
            if (slot < 0) continue;
            if (slot < MS_MAX_SLOTS) vc->rx_video[slot]++;

            uint64_t now = video_time_ms();
            VidSlot *v = vid_acquire(vc, slot);
            if (!v) continue;
            /* Recency for the pool is arrival, not successful decode: a sender
             * still waiting for its first keyframe is being heard and must not
             * be the one evicted. */
            v->last_ms = now;

            /* Reassembly is keyed by (this slot, frame id). Sharing one
             * receiver across senders spliced fragments from two of them into
             * a single corrupt frame whenever their ids coincided - and they
             * do, every sender's ids start at 0 - while the shared
             * last_completed_frame_id made whichever sender was numerically
             * behind look permanently stale and dropped all of it. */
            video_frag_receiver_expire(&v->frag, now);

            uint32_t completed_fid = 0;
            int frame_size = video_frag_receiver_push(&v->frag,
                                                      dec_buf, (int)frag_len,
                                                      yuv_buf, VC_MAX_VP8_FRAME,
                                                      &completed_fid);
            if (frame_size <= 0) continue;

            int dec_w = 0, dec_h = 0;
            int yuv_size = video_decoder_decode(v->dec, yuv_buf, frame_size,
                                                yuv_dec, VC_MAX_YUV_FRAME,
                                                &dec_w, &dec_h);
            if (yuv_size <= 0 || dec_w <= 0 || dec_h <= 0) continue;
            v->frames++;

            /* Every participant keeps its own picture. Nothing is chosen
             * between them any more; the window is a grid. */
#ifdef _WIN32
            EnterCriticalSection(&vc->disp_lock);
#else
            pthread_mutex_lock(&vc->disp_lock);
#endif
            if (!v->yuv || v->yuv_cap < (size_t)yuv_size) {
                free(v->yuv);
                v->yuv = (uint8_t *)malloc((size_t)yuv_size);
                v->yuv_cap = v->yuv ? (size_t)yuv_size : 0;
            }
            if (v->yuv) {
                memcpy(v->yuv, yuv_dec, (size_t)yuv_size);
                v->w = dec_w;
                v->h = dec_h;
                v->pic_ms = now;
                /* Only for sizing the black frame on peer timeout. */
                vc->disp_width = dec_w;
                vc->disp_height = dec_h;
                atomic_store(&vc->disp_new_frame, 1);
            }
#ifdef _WIN32
            LeaveCriticalSection(&vc->disp_lock);
#else
            pthread_mutex_unlock(&vc->disp_lock);
#endif
            continue;
        }

        /* Stats packet. Stats are drawn from the sender's video counter, so
         * the video key decrypts them: one counter domain, one key. */
        if (pkt_type == PKT_TYPE_STATS) {
            uint8_t plain[64];
            size_t plain_len = 0;
            StatsPayload sp;
            if (decrypt_from_sender(vc, rbuf, (size_t)n, MK_STREAM_VIDEO,
                                    plain, sizeof plain, &plain_len) >= 0 &&
                plain_len >= sizeof(StatsPayload)) {
                memcpy(&sp, plain, sizeof sp);
                quality_record_peer_stats(&vc->quality, sp.packets_received, sp.packets_lost);

                /* RTT: sp.rtt_ms = echo of our ping + hold time
                   sp.reserved = peer's current ping timestamp */
                /* The echo is addressed to nobody. A participant echoes
                 * whichever peer it heard from last, and every participant
                 * receives it, so in a group call most echoes carry a
                 * timestamp taken on a third machine's clock - and
                 * subtracting that from ours yields the difference between
                 * two unrelated uptimes.
                 *
                 * That is not a hypothesis. It is where the
                 * "[quality] RTT 248084855 ms (critical), capping to LOW" in
                 * a live three-way call came from: 2.9 days, which pinned
                 * every sender at 320x240 for the whole call.
                 *
                 * Foreign values are spread over the full 32-bit millisecond
                 * range, so demanding a plausible one keeps ours and discards
                 * theirs - the odds of a third machine's clock landing within
                 * a few seconds of ours are about one in a million per
                 * packet. What survives is a real round trip to a real peer:
                 * whichever one echoed us last, not necessarily the worst
                 * path. Naming the peer would need a field in the stats
                 * payload and a wire break on both platforms; this needs
                 * neither, and it is the difference between a usable number
                 * and a catastrophic one. */
                if (sp.rtt_ms != 0) {
                    uint32_t now32 = (uint32_t)(video_time_ms() & 0xFFFFFFFF);
                    uint32_t rtt = now32 - sp.rtt_ms;
                    if (rtt <= VC_RTT_SANE_MAX_MS) vc->measured_rtt_ms = rtt;
                }
                vc->last_peer_ping_ts = sp.reserved;
                vc->peer_ping_recv_time = video_time_ms();

                /* Feed actual measured RTT to quality controller */
                sp.rtt_ms = vc->measured_rtt_ms;
                quality_update(&vc->quality, &sp, video_time_ms());

                /* Update overlay */
                if (vc->display)
                    video_display_set_rtt(vc->display, vc->measured_rtt_ms);
            }
            continue;
        }
    }

    free(rbuf); free(dec_buf); free(yuv_buf); free(opus_buf); free(pcm);
    free(yuv_dec);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== Thread: Display (SDL event loop) ===== */

static THREAD_RET th_disp_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs *)arg;
    VideoCall *vc = ta->vc;
    free(ta);

    /* Open display immediately (show black screen until first frame arrives) */
    int w = vc->capture_width;
    int h = vc->capture_height;
    if (w <= 0) w = 640;
    if (h <= 0) h = 480;

    if (video_display_open(&vc->display, "F.E.A.R. Video Call", w, h) != 0) {
        fprintf(stderr, "Failed to open video display\n");
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    /* Render initial black frame (Y=0, U=128, V=128) */
    {
        int black_size = w * h * 3 / 2;
        uint8_t *black = (uint8_t *)calloc(1, black_size);
        if (black) {
            memset(black + w * h, 128, w * h / 2);
            video_display_render(vc->display, black, w, h);
            free(black);
        }
    }

    atomic_store(&vc->display_ready, 1);

    while (atomic_load(&vc->running)) {
        /* Process SDL events */
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_EVENT_QUIT) {
                atomic_store(&vc->running, 0);
            }
        }

        /* Render new frame if available */
        if (atomic_load(&vc->disp_new_frame)) {
            atomic_store(&vc->disp_new_frame, 0);
            vc_render_frame(vc);
        } else {
            msleep(16);
        }
    }

    video_display_close(vc->display);
    vc->display = NULL;

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ===== Audio initialization ===== */

static int audio_init_ports(VideoCall *vc, int input_device_id, int output_device_id) {
    PaError pe = Pa_Initialize();
    if (pe != paNoError) {
        fprintf(stderr, "PortAudio init error: %s\n", Pa_GetErrorText(pe));
        return -1;
    }

    PaStreamParameters inParams, outParams;
    memset(&inParams, 0, sizeof(inParams));
    memset(&outParams, 0, sizeof(outParams));

    inParams.device = (input_device_id >= 0) ? input_device_id : Pa_GetDefaultInputDevice();
    if (inParams.device != paNoDevice) {
        const PaDeviceInfo *indev = Pa_GetDeviceInfo(inParams.device);
        if (indev) {
            inParams.channelCount = VC_CHANNELS;
            inParams.sampleFormat = paInt16;
            inParams.suggestedLatency = indev->defaultLowInputLatency;
        } else {
            inParams.device = paNoDevice;
        }
    }

    outParams.device = (output_device_id >= 0) ? output_device_id : Pa_GetDefaultOutputDevice();
    if (outParams.device != paNoDevice) {
        const PaDeviceInfo *outdev = Pa_GetDeviceInfo(outParams.device);
        if (outdev) {
            outParams.channelCount = VC_CHANNELS;
            outParams.sampleFormat = paInt16;
            outParams.suggestedLatency = outdev->defaultLowOutputLatency;
        } else {
            outParams.device = paNoDevice;
        }
    }

    /* Open input stream */
    if (inParams.device != paNoDevice) {
        pe = Pa_OpenStream(&vc->in_stream, &inParams, NULL, VC_SAMPLE_RATE,
                           VC_FRAME_SAMPLES, paClipOff, NULL, NULL);
        if (pe != paNoError) vc->in_stream = NULL;
    }
    if (vc->in_stream == NULL) {
        pe = Pa_OpenDefaultStream(&vc->in_stream, VC_CHANNELS, 0, paInt16,
                                  VC_SAMPLE_RATE, VC_FRAME_SAMPLES, NULL, NULL);
        if (pe != paNoError) {
            fprintf(stderr, "Warning: Audio input disabled\n");
            vc->in_stream = NULL;
        }
    }

    /* Open output stream */
    if (outParams.device != paNoDevice) {
        pe = Pa_OpenStream(&vc->out_stream, NULL, &outParams, VC_SAMPLE_RATE,
                           VC_FRAME_SAMPLES, paClipOff, NULL, NULL);
        if (pe != paNoError) vc->out_stream = NULL;
    }
    if (vc->out_stream == NULL) {
        pe = Pa_OpenDefaultStream(&vc->out_stream, 0, VC_CHANNELS, paInt16,
                                  VC_SAMPLE_RATE, VC_FRAME_SAMPLES, NULL, NULL);
        if (pe != paNoError) {
            fprintf(stderr, "Warning: Audio output disabled\n");
            vc->out_stream = NULL;
        }
    }

    if (vc->in_stream) {
        if (Pa_StartStream(vc->in_stream) != paNoError) {
            Pa_CloseStream(vc->in_stream);
            vc->in_stream = NULL;
        }
    }
    if (vc->out_stream) {
        if (Pa_StartStream(vc->out_stream) != paNoError) {
            Pa_CloseStream(vc->out_stream);
            vc->out_stream = NULL;
        }
    }

    printf("Audio: input %s, output %s\n",
           vc->in_stream ? "enabled" : "disabled",
           vc->out_stream ? "enabled" : "disabled");
    return 0;
}

static int audio_init_codec(VideoCall *vc) {
    int err = 0;
    vc->enc = opus_encoder_create(VC_SAMPLE_RATE, VC_CHANNELS, OPUS_APPLICATION_VOIP, &err);
    if (!vc->enc || err != OPUS_OK) return -1;

    opus_encoder_ctl(vc->enc, OPUS_SET_BITRATE(128000));
    opus_encoder_ctl(vc->enc, OPUS_SET_COMPLEXITY(5));
    opus_encoder_ctl(vc->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    opus_encoder_ctl(vc->enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(vc->enc, OPUS_SET_PACKET_LOSS_PERC(10));

    /* Decoders are created per participant when that participant is first
     * heard, not here: one decoder cannot serve several senders. Only the
     * rings and the lock exist up front. */
    for (int i = 0; i < VC_MAX_MIX; i++) {
        vc->mix[i].slot = -1;
        vc->mix[i].dec = NULL;
        vc->mix[i].last_ms = 0;
        vc->mix[i].prefilled = 0;
        vc->mix[i].frames = 0;
        if (pcmring_init(&vc->mix[i].ring, 32) != 0) {
            fprintf(stderr, "pcmring_init failed for mix slot %d\n", i);
            for (int j = 0; j < i; j++) pcmring_free(&vc->mix[j].ring);
            return -1;
        }
    }
#ifdef _WIN32
    InitializeCriticalSection(&vc->mix_lock);
#else
    pthread_mutex_init(&vc->mix_lock, NULL);
#endif
    vc->mix_ready = 1;

    return 0;
}

/* ===== Lifecycle ===== */

static void video_call_stop(VideoCall *vc) {
    if (!vc) return;
    atomic_store(&vc->running, 0);

#ifdef _WIN32
    if (vc->th_vsend) { WaitForSingleObject(vc->th_vsend, 5000); CloseHandle(vc->th_vsend); }
    if (vc->th_asend) { WaitForSingleObject(vc->th_asend, 5000); CloseHandle(vc->th_asend); }
    if (vc->th_recv)  { WaitForSingleObject(vc->th_recv, 5000);  CloseHandle(vc->th_recv); }
    if (vc->th_play)  { WaitForSingleObject(vc->th_play, 5000);  CloseHandle(vc->th_play); }
#else
    if (vc->th_vsend) { pthread_join(vc->th_vsend, NULL); vc->th_vsend = 0; }
    if (vc->th_asend) { pthread_join(vc->th_asend, NULL); vc->th_asend = 0; }
    if (vc->th_recv)  { pthread_join(vc->th_recv, NULL);  vc->th_recv = 0; }
    if (vc->th_play)  { pthread_join(vc->th_play, NULL);  vc->th_play = 0; }
#endif

    if (vc->in_stream) { Pa_StopStream(vc->in_stream); Pa_CloseStream(vc->in_stream); }
    if (vc->out_stream) { Pa_StopStream(vc->out_stream); Pa_CloseStream(vc->out_stream); }
    Pa_Terminate();

    if (vc->enc) opus_encoder_destroy(vc->enc);

    video_capture_close(vc->capture);
    video_encoder_close(vc->v_enc);
    if (vc->display) { video_display_close(vc->display); vc->display = NULL; }

    if (vc->tcp_sock) CLOSESOCK(vc->tcp_sock);
    if (vc->sock) CLOSESOCK(vc->sock);
    for (int i = 0; i < VC_MAX_VIDEO; i++) free(vc->vid[i].yuv);
    free(vc->local_yuv);

#ifdef _WIN32
    DeleteCriticalSection(&vc->disp_lock);
    if (vc->tcp_sock) DeleteCriticalSection(&vc->tcp_send_lock);
#else
    pthread_mutex_destroy(&vc->disp_lock);
    if (vc->relay_mode) pthread_mutex_destroy(&vc->tcp_send_lock);
#endif

    /* One pair of lines per participant we installed: what decrypted, and
     * what actually reached the user. They are not the same number and the
     * difference is the whole point - per-sender keys make every packet
     * authenticate, which looks like success right up until you notice
     * "decrypted 441 mixed 0", one decoder shared by three senders. */
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (!vc->senders.slots[i].used) continue;
        const uint8_t *sid = vc->senders.slots[i].sid;
        uint64_t mixed = 0, decoded = 0, shown = 0;
        for (int k = 0; k < VC_MAX_MIX; k++) {
            if (vc->mix[k].slot == i) { mixed = vc->mix[k].frames; break; }
        }
        for (int k = 0; k < VC_MAX_VIDEO; k++) {
            if (vc->vid[k].slot == i) {
                decoded = vc->vid[k].frames;
                shown = vc->vid[k].shown;
                break;
            }
        }
        printf("[MEDIA] peer %02x%02x%02x decrypted %llu mixed %llu\n",
               sid[0], sid[1], sid[2],
               (unsigned long long)vc->rx_audio[i], (unsigned long long)mixed);
        printf("[VIDEO] peer %02x%02x%02x decrypted %llu decoded %llu shown %llu\n",
               sid[0], sid[1], sid[2],
               (unsigned long long)vc->rx_video[i],
               (unsigned long long)decoded, (unsigned long long)shown);
    }
    fflush(stdout);

    mix_teardown(vc);
    vid_teardown(vc);

    /* Secure wipe: every key, salt and identity secret this call held. */
    ms_clear(&vc->senders);
    sodium_memzero(vc->send_key, sizeof(vc->send_key));
    sodium_memzero(vc->hello_key, sizeof(vc->hello_key));
    sodium_memzero(vc->own_salt, sizeof(vc->own_salt));
    sodium_memzero(vc->own_sid, sizeof(vc->own_sid));
    sodium_memzero(vc->call_id, sizeof(vc->call_id));
    sodium_memzero(vc->identity_sk, sizeof(vc->identity_sk));
    sodium_memzero(vc->master_key, sizeof(vc->master_key));

    free(vc);
}

/* ===== Key I/O helpers (same as audio_call) ===== */

static int read_key_from_file(const char *filename, char *buffer, size_t bufsize) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open key file '%s'\n", filename);
        return -1;
    }
    if (!fgets(buffer, (int)bufsize, f)) {
        fprintf(stderr, "Error: Cannot read from key file '%s'\n", filename);
        fclose(f);
        return -1;
    }
    fclose(f);

    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || buffer[len-1] == ' ')) {
        buffer[len-1] = '\0';
        len--;
    }
    return (len > 0) ? 0 : -1;
}

static int read_key_from_stdin(char *buffer, size_t bufsize, int interactive) {
    if (interactive) {
        fprintf(stderr, "Enter video call key (64 hex chars): ");
        fflush(stderr);
    }
    if (!fgets(buffer, (int)bufsize, stdin)) {
        fprintf(stderr, "Error: Failed to read key from stdin\n");
        return -1;
    }
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || buffer[len-1] == ' ')) {
        buffer[len-1] = '\0';
        len--;
    }
    return (len > 0) ? 0 : -1;
}

/* ===== Signal handling ===== */

static volatile atomic_int g_sigint = 0;

#ifdef _WIN32
static BOOL WINAPI ctrlc_handler(DWORD ev) {
    if (ev == CTRL_C_EVENT) { atomic_store(&g_sigint, 1); return TRUE; }
    return FALSE;
}
#else
static void ctrlc_handler(int sig) { (void)sig; atomic_store(&g_sigint, 1); }
#endif

static void setup_signal(void) {
#ifdef _WIN32
    SetConsoleCtrlHandler(ctrlc_handler, TRUE);
#else
    struct sigaction sa;
    sa.sa_handler = ctrlc_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
#endif
}

/* ===== Main ===== */

static void print_usage(const char *argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s genkey\n"
        "  %s listdevices\n"
        "  %s call <ip> <port> [options] [local_port]\n"
        "  %s listen <port> [options]\n"
        "  %s relay <ip> <port> --room ROOM --name NAME [options]\n"
        "  %s hub <port>\n"
        "\n"
        "Options:\n"
        "  --call-id HEX32       Call identifier, 32 hex chars (REQUIRED)\n"
        "  --key-file FILE       Read key from file\n"
        "  --quality low|medium|high  Quality preset (default: medium)\n"
        "  --adaptive            Enable adaptive quality (default)\n"
        "  --width N             Custom width\n"
        "  --height N            Custom height\n"
        "  --fps N               Custom framerate\n"
        "  --bitrate N           Custom bitrate in kbps\n"
        "  --camera DEVICE       Camera device path\n"
        "  --audio-input N       Audio input device ID\n"
        "  --audio-output N      Audio output device ID\n"
        "  --no-video            Disable video (audio only)\n"
        "  --no-audio            Disable audio (video only)\n"
        "  --no-camera           No local camera (receive-only video)\n"
        "  --room ROOM           Room name (relay mode)\n"
        "  --name NAME           User name (relay mode)\n"
        "\n"
        "Key input: --key-file > stdin > deprecated CLI arg\n",
        argv0, argv0, argv0, argv0, argv0, argv0);
}

typedef struct {
    const char *keyfile;
    QualityLevel quality;
    int adaptive;
    int width, height, fps, bitrate;
    char camera[256];
    int audio_input, audio_output;
    int no_video, no_audio, no_camera;
    uint16_t local_port;
    const char *identity_file;
    int no_sign;
    const char *relay_room;
    const char *relay_name;
} CallOptions;

static void options_init(CallOptions *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->quality = QUALITY_MEDIUM;
    opts->adaptive = 1;
    opts->width = 0;
    opts->height = 0;
    opts->fps = 0;
    opts->bitrate = 0;
    opts->audio_input = -1;
    opts->audio_output = -1;
}

static int parse_options(int argc, char **argv, int start_idx, CallOptions *opts) {
    for (int i = start_idx; i < argc; i++) {
        if (strcmp(argv[i], "--call-id") == 0 && i + 1 < argc) {
            /* Parsed and validated only for now. Step 5 of the group-call
             * migration makes it mandatory and binds it into every media
             * key, so nothing on the wire changes here. */
            if (mk_call_id_parse(argv[i + 1], g_call_id) != 0) {
                fprintf(stderr, "Error: --call-id must be %d hex characters and not all zero\n",
                        MK_CALLID_BYTES * 2);
                return 1;
            }
            g_have_call_id = 1;
            i++;   /* the loop's own i++ steps past the value */
        } else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) {
            opts->keyfile = argv[++i];
        } else if (strcmp(argv[i], "--quality") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "low") == 0) opts->quality = QUALITY_LOW;
            else if (strcmp(argv[i], "medium") == 0) opts->quality = QUALITY_MEDIUM;
            else if (strcmp(argv[i], "high") == 0) opts->quality = QUALITY_HIGH;
        } else if (strcmp(argv[i], "--adaptive") == 0) {
            opts->adaptive = 1;
        } else if (strcmp(argv[i], "--width") == 0 && i + 1 < argc) {
            opts->width = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--height") == 0 && i + 1 < argc) {
            opts->height = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fps") == 0 && i + 1 < argc) {
            opts->fps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bitrate") == 0 && i + 1 < argc) {
            opts->bitrate = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--camera") == 0 && i + 1 < argc) {
            strncpy(opts->camera, argv[++i], sizeof(opts->camera) - 1);
        } else if (strcmp(argv[i], "--audio-input") == 0 && i + 1 < argc) {
            opts->audio_input = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--audio-output") == 0 && i + 1 < argc) {
            opts->audio_output = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-video") == 0) {
            opts->no_video = 1;
        } else if (strcmp(argv[i], "--no-audio") == 0) {
            opts->no_audio = 1;
        } else if (strcmp(argv[i], "--no-camera") == 0) {
            opts->no_camera = 1;
        } else if (strcmp(argv[i], "--identity-file") == 0 && i + 1 < argc) {
            opts->identity_file = argv[++i];
        } else if (strcmp(argv[i], "--no-sign") == 0) {
            opts->no_sign = 1;
        } else if (strcmp(argv[i], "--room") == 0 && i + 1 < argc) {
            opts->relay_room = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            opts->relay_name = argv[++i];
        } else {
            /* Treat as local port if numeric */
            char *endptr;
            long val = strtol(argv[i], &endptr, 10);
            if (*endptr == '\0' && val > 0 && val <= 65535) {
                opts->local_port = (uint16_t)val;
            }
        }
    }
    return 0;
}

static int resolve_key(const CallOptions *opts, uint8_t key[AES_GCM_KEY_LEN]) {
    static char key_buffer[256];
    memset(key_buffer, 0, sizeof(key_buffer));
    const char *hexkey = NULL;

    if (opts->keyfile) {
        if (read_key_from_file(opts->keyfile, key_buffer, sizeof(key_buffer)) != 0)
            return -1;
        hexkey = key_buffer;
    } else {
        int is_interactive = isatty(fileno(stdin));
        if (read_key_from_stdin(key_buffer, sizeof(key_buffer), is_interactive) != 0)
            return -1;
        hexkey = key_buffer;
    }

    if (hex2bytes(hexkey, key, AES_GCM_KEY_LEN) != 0) {
        fprintf(stderr, "Invalid key (must be 64 hex chars)\n");
        return -1;
    }
    return 0;
}

static int start_video_call(const char *remote_ip, uint16_t remote_port,
                             const CallOptions *opts) {
    /* Mandatory. Every media key, every sender tag and the HELLO2 MAC key are
     * bound to the call_id, so there is nothing to derive without one, and an
     * all-zero default would silently drop the cross-call replay barrier. */
    if (!g_have_call_id) {
        fprintf(stderr,
                "Error: --call-id is required (%d hex characters, from the call invite).\n"
                "       Every media key is bound to it; a call cannot start without one.\n",
                MK_CALLID_BYTES * 2);
        return -1;
    }
    if (net_init_once() != 0) return -1;
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return -1; }

    /* Initialize SDL3 */
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return -1;
    }

    VideoCall *vc = (VideoCall *)calloc(1, sizeof(VideoCall));
    if (!vc) return -1;

    /* Resolve the shared call key. Everything derived from it waits until the
     * identity is known, because our idbind is one of the inputs. */
    if (resolve_key(opts, vc->master_key) != 0) { free(vc); SDL_Quit(); return -1; }
    memcpy(vc->call_id, g_call_id, MK_CALLID_BYTES);

    atomic_store(&vc->peers_known, 0);
    atomic_store(&vc->audio_seq_tx, 0);
    atomic_store(&vc->video_seq_tx, 0);
    atomic_store(&vc->running, 1);
    atomic_store(&vc->display_ready, 0);
    atomic_store(&vc->disp_new_frame, 0);
    atomic_store(&vc->last_recv_time, 0);
    atomic_store(&vc->peer_connected, 0);

    /* Load identity (optional) */
    vc->has_identity = 0;
    vc->peer_verified = 0;
    identity_default_known_keys_path(vc->known_keys_path, sizeof(vc->known_keys_path));
    if (!opts->no_sign) {
        char id_path[512];
        if (opts->identity_file) {
            strncpy(id_path, opts->identity_file, sizeof(id_path) - 1);
            id_path[sizeof(id_path) - 1] = '\0';
        } else {
            identity_default_path(id_path, sizeof(id_path));
        }
        if (identity_load(id_path, vc->identity_pk, vc->identity_sk) == 0) {
            vc->has_identity = 1;
            char fp[IDENTITY_FINGERPRINT_LEN];
            identity_pk_fingerprint(vc->identity_pk, fp);
            fprintf(stderr, "Identity loaded: %s\n", fp);
        }
    }

    /* Draw our salt and derive our whole send context. This has to come after
     * the identity load: idbind is our own public key when one is loaded and
     * 32 zero bytes otherwise, and getting it wrong changes every key we use.
     * It still runs before any thread starts, which is what the modules
     * require - nothing here may change mid-call. */
    if (vc_setup_media_keys(vc) != 0) {
        sodium_memzero(vc->master_key, sizeof vc->master_key);
        sodium_memzero(vc->identity_sk, sizeof vc->identity_sk);
        free(vc); SDL_Quit(); return -1;
    }

#ifdef _WIN32
    InitializeCriticalSection(&vc->disp_lock);
#else
    pthread_mutex_init(&vc->disp_lock, NULL);
#endif

    vc->video_enabled = !opts->no_video;
    vc->audio_enabled = !opts->no_audio;

    /* Setup quality */
    QualityLevel qlevel = opts->quality;
    if (opts->width > 0 && opts->height > 0) {
        qlevel = QUALITY_CUSTOM;
    }
    quality_init(&vc->quality, qlevel, opts->adaptive);

    if (qlevel == QUALITY_CUSTOM) {
        const VideoQualityPreset *base = &QUALITY_PRESETS[opts->quality];
        quality_set_custom(&vc->quality,
                           opts->width > 0 ? opts->width : base->width,
                           opts->height > 0 ? opts->height : base->height,
                           opts->fps > 0 ? opts->fps : base->fps,
                           opts->bitrate > 0 ? opts->bitrate : base->bitrate_kbps);
    }

    const VideoQualityPreset *preset = quality_get_preset(&vc->quality);
    vc->capture_width = preset->width;
    vc->capture_height = preset->height;
    vc->capture_fps = preset->fps;
    if (opts->camera[0]) {
        memcpy(vc->camera_device, opts->camera,
               strlen(opts->camera) < sizeof(vc->camera_device) - 1
               ? strlen(opts->camera) : sizeof(vc->camera_device) - 1);
    }

    /* Rendered-participant pool for video. The audio pool is set up in
     * audio_init_codec, alongside the encoder, exactly as audio_call does it.
     * Both run before any thread starts. */
    for (int i = 0; i < VC_MAX_VIDEO; i++) {
        vc->vid[i].slot = -1;
        vc->vid[i].dec = NULL;
        vc->vid[i].last_ms = 0;
        vc->vid[i].frames = 0;
        vc->vid[i].shown = 0;
        video_frag_receiver_init(&vc->vid[i].frag);
    }

    /* Socket */
    vc->sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (vc->sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "socket() failed\n");
        free(vc); SDL_Quit(); return -1;
    }

    /* Bound how long recvfrom may block, so the receive thread notices
     * vc->running going to zero. Without it the thread sits in recvfrom
     * forever whenever the call is quiet, video_call_stop blocks in
     * pthread_join, and Ctrl+C never completes - which also means none of the
     * teardown below ever runs: not the report, not the key wiping. Same
     * 200 ms as audio_call. */
    {
#ifdef _WIN32
        DWORD rcv_to = 200;
        setsockopt(vc->sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&rcv_to, sizeof rcv_to);
#else
        struct timeval rcv_to;
        rcv_to.tv_sec = 0;
        rcv_to.tv_usec = 200000;
        setsockopt(vc->sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof rcv_to);
#endif
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(opts->local_port);
    if (bind(vc->sock, (struct sockaddr *)&local, sizeof(local)) == SOCK_ERR) {
        fprintf(stderr, "bind() failed (port %u)\n", opts->local_port);
        CLOSESOCK(vc->sock); free(vc); SDL_Quit(); return -1;
    }

    vc->peer_set = 0;
    vc->relay_mode = 0;
    if (remote_ip && remote_port != 0) {
        memset(&vc->peer, 0, sizeof(vc->peer));
        vc->peer.sin_family = AF_INET;
        vc->peer.sin_port = htons(remote_port);
        if (resolve_host_v4(remote_ip, &vc->peer.sin_addr) != 0) {
            fprintf(stderr, "cannot resolve host %s\n", remote_ip);
            CLOSESOCK(vc->sock); free(vc); SDL_Quit(); return -1;
        }
        vc->peer_set = 1;
    }

    /* Relay mode: if room+name provided, connect via TCP to server */
    if (opts->relay_room && opts->relay_name) {
        vc->relay_mode = 1;
        strncpy(vc->relay_room, opts->relay_room, sizeof(vc->relay_room) - 1);
        vc->relay_room[sizeof(vc->relay_room) - 1] = '\0';
        strncpy(vc->relay_name, opts->relay_name, sizeof(vc->relay_name) - 1);
        vc->relay_name[sizeof(vc->relay_name) - 1] = '\0';

        /* TCP relay: connect to server and register */
        if (remote_ip && remote_port != 0) {
#ifdef _WIN32
            InitializeCriticalSection(&vc->tcp_send_lock);
#else
            pthread_mutex_init(&vc->tcp_send_lock, NULL);
#endif
            if (tcp_relay_connect(vc, remote_ip, remote_port) != 0) {
                CLOSESOCK(vc->sock); free(vc); SDL_Quit(); return -1;
            }
            if (tcp_relay_register(vc) != 0) {
                fprintf(stderr, "TCP relay registration failed\n");
                CLOSESOCK(vc->tcp_sock); CLOSESOCK(vc->sock);
                free(vc); SDL_Quit(); return -1;
            }
            /* Set peer_set=1 so send guards pass (actual routing goes through TCP) */
            vc->peer_set = 1;
        }
    }

    /* Initialize audio */
    if (vc->audio_enabled) {
        if (audio_init_ports(vc, opts->audio_input, opts->audio_output) != 0) {
            fprintf(stderr, "Warning: Audio initialization failed, continuing without audio\n");
            vc->audio_enabled = 0;
        } else if (audio_init_codec(vc) != 0) {
            fprintf(stderr, "Warning: Opus codec failed, continuing without audio\n");
            vc->audio_enabled = 0;
        }
    }

    /* Initialize video */
    if (vc->video_enabled) {
        if (opts->no_camera) {
            fprintf(stderr, "No camera mode: receive-only video\n");
            vc->capture = NULL;
        } else {
            const char *cam = vc->camera_device[0] ? vc->camera_device : NULL;
            if (video_capture_open(&vc->capture, cam,
                                   vc->capture_width, vc->capture_height, vc->capture_fps) != 0) {
                fprintf(stderr, "Warning: Camera not available, continuing without local video\n");
                vc->capture = NULL;
            }
        }

        int actual_w = vc->capture_width, actual_h = vc->capture_height;
        if (vc->capture) {
            video_capture_get_size(vc->capture, &actual_w, &actual_h);
            vc->capture_width = actual_w;
            vc->capture_height = actual_h;

            if (video_encoder_open(&vc->v_enc, actual_w, actual_h,
                                   vc->capture_fps, preset->bitrate_kbps) != 0) {
                fprintf(stderr, "Warning: VP8 encoder failed\n");
                vc->v_enc = NULL;
            }
        }

        /* No decoder is opened here. One per rendered participant is created
         * on the first fragment from that participant (see vid_acquire),
         * because one VP8 decoder fed by several senders decodes each one's
         * frames against another's reference frames. */
    }

    /* Send initial HELLO */
    if (vc->peer_set) send_hello(vc);

    /* Start threads (recv, asend, vsend, play). Play-out is its own thread
     * now: with several senders the receive loop runs several times per frame
     * period, so it cannot be what paces the output device. */
    ThreadArgs *a1 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs));
    ThreadArgs *a2 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs));
    ThreadArgs *a3 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs));
    ThreadArgs *a4 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs));
    if (!a1 || !a2 || !a3 || !a4) {
        free(a1); free(a2); free(a3); free(a4);
        fprintf(stderr, "out of memory starting call threads\n");
        video_call_stop(vc); SDL_Quit(); return -1;
    }
    a1->vc = vc; a2->vc = vc; a3->vc = vc; a4->vc = vc;

#ifdef _WIN32
    vc->th_recv  = CreateThread(NULL, 0, th_recv_func, a1, 0, NULL);
    vc->th_asend = CreateThread(NULL, 0, th_asend_func, a2, 0, NULL);
    vc->th_vsend = CreateThread(NULL, 0, th_vsend_func, a3, 0, NULL);
    vc->th_play  = CreateThread(NULL, 0, th_play_func, a4, 0, NULL);
#else
    pthread_create(&vc->th_recv,  NULL, th_recv_func, a1);
    pthread_create(&vc->th_asend, NULL, th_asend_func, a2);
    pthread_create(&vc->th_vsend, NULL, th_vsend_func, a3);
    pthread_create(&vc->th_play,  NULL, th_play_func, a4);
#endif

    /* Open display on main thread (SDL requires this on Windows/macOS) */
    if (vc->video_enabled) {
        int dw = vc->capture_width > 0 ? vc->capture_width : 640;
        int dh = vc->capture_height > 0 ? vc->capture_height : 480;
        if (video_display_open(&vc->display, "F.E.A.R. Video Call", dw, dh) == 0) {
            int bs = dw * dh * 3 / 2;
            uint8_t *black = (uint8_t *)calloc(1, bs);
            if (black) {
                memset(black + dw * dh, 128, dw * dh / 2);
                video_display_render(vc->display, black, dw, dh);
                free(black);
            }
            atomic_store(&vc->display_ready, 1);
        }
    }

    setup_signal();

    if (remote_ip) {
        printf("Video call to %s:%u (press Ctrl+C to stop)\n", remote_ip, remote_port);
    } else {
        printf("Listening on *:%u (press Ctrl+C to stop)\n", opts->local_port);
    }

    /* Main loop: SDL event handling + frame rendering + peer timeout */
    #define PEER_TIMEOUT_MS 5000
    #define HELLO_REANNOUNCE_MS 1000
    #define HELLO_KEEPALIVE_MS 5000
    uint64_t last_announce_ms = video_time_ms();
    while (!atomic_load(&g_sigint) && atomic_load(&vc->running)) {
        /* Announce for the whole call: quickly while nobody has answered,
         * because the first HELLO is simply lost if the other side is not up
         * yet, and slowly afterwards, because the single reply a newcomer
         * draws from us is one packet with no retransmission behind it.
         *
         * This loop used to stop at the first peer, and that is exactly what
         * a three-device call fell over on: two participants found each other
         * and went quiet, a phone joined afterwards, and its HELLO was heard
         * by both while neither reply reached it. It sent video everyone
         * could see and received nothing, then timed out - five times in a
         * row. audio_call has carried the two-rate shape since the group work
         * landed; video never got it, which is also why an audio call to the
         * same phone had always worked.
         *
         * A HELLO2 carries only our own salt, ms_install is idempotent per
         * salt, and a repeat draws no reply of its own, so this resets
         * nothing at the peer and cannot become a handshake storm. */
        if (vc->peer_set || vc->tcp_sock) {
            uint64_t now_ms = video_time_ms();
            uint64_t hello_gap = atomic_load(&vc->peers_known) == 0
                                     ? HELLO_REANNOUNCE_MS
                                     : HELLO_KEEPALIVE_MS;
            if (now_ms - last_announce_ms >= hello_gap) {
                if (vc->relay_mode && !vc->tcp_sock) send_udp_registration(vc);
                send_hello(vc);
                last_announce_ms = now_ms;
            }
        }

        if (vc->display) {
            SDL_Event ev;
            while (SDL_PollEvent(&ev)) {
                if (ev.type == SDL_EVENT_QUIT) {
                    atomic_store(&vc->running, 0);
                }
            }

            /* Peer timeout detection: show black frame when peer stops sending */
            uint64_t lr = atomic_load(&vc->last_recv_time);
            if (lr > 0 && atomic_load(&vc->peer_connected)) {
                uint64_t now = video_time_ms();
                if (now - lr > PEER_TIMEOUT_MS) {
                    atomic_store(&vc->peer_connected, 0);
                    printf("Peer disconnected (no data for %d ms)\n", PEER_TIMEOUT_MS);
                    /* Render black frame */
                    int bw = vc->disp_width > 0 ? vc->disp_width : 640;
                    int bh = vc->disp_height > 0 ? vc->disp_height : 480;
                    int bs = bw * bh * 3 / 2;
                    uint8_t *black = (uint8_t *)calloc(1, bs);
                    if (black) {
                        memset(black + bw * bh, 128, bw * bh / 2);
                        video_display_render(vc->display, black, bw, bh);
                        free(black);
                    }
                }
            }

            if (atomic_load(&vc->disp_new_frame)) {
                atomic_store(&vc->disp_new_frame, 0);
                vc_render_frame(vc);
            }

            msleep(16);
        } else {
            msleep(100);
        }
    }

    video_call_stop(vc);
    SDL_Quit();
    printf("Video call ended\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        if (sodium_init() < 0) return 1;
        uint8_t key[AES_GCM_KEY_LEN];
        randombytes_buf(key, sizeof(key));
        for (size_t i = 0; i < sizeof(key); ++i) printf("%02x", key[i]);
        printf("\n");
        fprintf(stderr, "Video call key generated successfully.\n");
        fprintf(stderr, "IMPORTANT: Share this key securely with call participants.\n");
        return 0;
    }

    if (strcmp(argv[1], "listdevices") == 0) {
        /* List audio devices */
        PaError pe = Pa_Initialize();
        if (pe == paNoError) {
            int numDevices = Pa_GetDeviceCount();
            printf("=== Audio Devices ===\n");
            printf("Total: %d, Default input: %d, Default output: %d\n\n",
                   numDevices, Pa_GetDefaultInputDevice(), Pa_GetDefaultOutputDevice());

            for (int i = 0; i < numDevices; i++) {
                const PaDeviceInfo *info = Pa_GetDeviceInfo(i);
                if (!info) continue;
                const PaHostApiInfo *hostInfo = Pa_GetHostApiInfo(info->hostApi);
                printf("Device %d: %s (%s)\n", i, info->name,
                       hostInfo ? hostInfo->name : "Unknown");
                printf("  Max input channels: %d\n", info->maxInputChannels);
                printf("  Max output channels: %d\n", info->maxOutputChannels);
                printf("\n");
            }
            Pa_Terminate();
        }

        /* List camera devices */
        printf("=== Camera Devices ===\n");
        video_capture_list_devices();
        return 0;
    }

    if (strcmp(argv[1], "hub") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s hub <bind_port>\n", argv[0]);
            return 1;
        }
        uint16_t port = (uint16_t)atoi(argv[2]);
        return hub_main(port);
    }

    if (strcmp(argv[1], "call") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s call <ip> <port> [options] [local_port]\n", argv[0]);
            return 1;
        }
        const char *ip = argv[2];
        uint16_t rport = (uint16_t)atoi(argv[3]);

        CallOptions opts;
        options_init(&opts);
        parse_options(argc, argv, 4, &opts);

        return start_video_call(ip, rport, &opts);
    }

    if (strcmp(argv[1], "listen") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s listen <port> [options]\n", argv[0]);
            return 1;
        }

        CallOptions opts;
        options_init(&opts);
        opts.local_port = (uint16_t)atoi(argv[2]);
        parse_options(argc, argv, 3, &opts);

        return start_video_call(NULL, 0, &opts);
    }

    if (strcmp(argv[1], "relay") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s relay <ip> <port> --room ROOM --name NAME [options]\n", argv[0]);
            return 1;
        }
        const char *ip = argv[2];
        uint16_t rport = (uint16_t)atoi(argv[3]);

        CallOptions opts;
        options_init(&opts);
        parse_options(argc, argv, 4, &opts);

        if (!opts.relay_room || !opts.relay_name) {
            fprintf(stderr, "Error: --room and --name are required for relay mode\n");
            return 1;
        }

        return start_video_call(ip, rport, &opts);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}
