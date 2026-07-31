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

/* AES-GCM constants */
#define AES_GCM_KEY_LEN   crypto_aead_aes256gcm_KEYBYTES
#define AES_GCM_NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define AES_GCM_ABYTES    crypto_aead_aes256gcm_ABYTES

/* Replay protection now lives in media_senders.h: one sliding window per
 * (sender, counter domain), fed only by ms_accept_seq and only after the AEAD
 * tag has verified. The single global window this file used to keep could not
 * survive a second sender, and it accepted arbitrarily large forward jumps. */

/* ===== VideoCall state ===== */

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

    /* Transmit counters, one per counter domain. Audio packets use the audio
     * counter; video fragments AND stats share the video counter, which is
     * exactly why they must also share the video key (see media_keys.h). */
    atomic_uint_fast64_t audio_seq_tx;
    atomic_uint_fast64_t video_seq_tx;

    /* Audio */
    PaStream *in_stream;
    PaStream *out_stream;
    OpusEncoder *enc;
    OpusDecoder *dec;
    PcmRing out_ring;

    /* Video */
    VideoCapture *capture;
    VideoEncoder *v_enc;
    VideoDecoder *v_dec;
    VideoDisplay *display;
    FragReceiver frag_recv;
    QualityController quality;

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
    HANDLE th_disp;
#else
    pthread_t th_vsend;
    pthread_t th_asend;
    pthread_t th_recv;
    pthread_t th_disp;
#endif
    atomic_int running;
    atomic_int display_ready;

    /* Shared frame buffer for display thread */
    uint8_t *disp_yuv;
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

    /* A peer that restarts draws a fresh salt and therefore arrives as a new
     * sender: its replay window starts clean in its own slot, but the
     * reassembler and the decoder still hold the previous session's leftovers,
     * whose frame ids restart at 0. Not on the very first announcement, when
     * there is nothing to clear. */
    if (before > 0) {
        printf("New participant, resetting reassembly and decoder\n");
        video_frag_receiver_free(&vc->frag_recv);
        video_frag_receiver_init(&vc->frag_recv);
        if (vc->v_dec) {
            video_decoder_close(vc->v_dec);
            vc->v_dec = NULL;
            video_decoder_open(&vc->v_dec);
        }
#ifdef _WIN32
        EnterCriticalSection(&vc->disp_lock);
#else
        pthread_mutex_lock(&vc->disp_lock);
#endif
        free(vc->disp_yuv);
        vc->disp_yuv = NULL;
        vc->disp_width = 0;
        vc->disp_height = 0;
        atomic_store(&vc->disp_new_frame, 0);
#ifdef _WIN32
        LeaveCriticalSection(&vc->disp_lock);
#else
        pthread_mutex_unlock(&vc->disp_lock);
#endif
    }

    /* Exactly one reply, so the new participant learns our salt. Repetition is
     * the announce loop's job, not this path's. */
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

    if (!rbuf || !dec_buf || !yuv_buf || !opus_buf || !pcm) {
        free(rbuf); free(dec_buf); free(yuv_buf); free(opus_buf); free(pcm);
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
            if (decrypt_from_sender(vc, rbuf, (size_t)n, MK_STREAM_AUDIO,
                                    opus_buf, VC_MAX_OPUS_BYTES, &opus_len) < 0) {
                continue;
            }

            int dec_samples = opus_decode(vc->dec, opus_buf, (opus_int32)opus_len,
                                           pcm, VC_FRAME_SAMPLES, 0);
            if (dec_samples <= 0) continue;
            if (dec_samples < VC_FRAME_SAMPLES) {
                memset(pcm + dec_samples * VC_CHANNELS, 0,
                       (VC_FRAME_SAMPLES - dec_samples) * VC_CHANNELS * sizeof(int16_t));
            }

            pcmring_push(&vc->out_ring, pcm);

            /* Latency control: drain old frames if buffer grows too large */
            #define MAX_PLAYOUT_FRAMES 20
            while (atomic_load(&vc->out_ring.count) > MAX_PLAYOUT_FRAMES) {
                int16_t discard[VC_FRAME_SAMPLES];
                pcmring_pop(&vc->out_ring, discard);
            }

            if (vc->out_stream &&
                atomic_load(&vc->out_ring.count) >= PLAYOUT_BUFFER_FRAMES) {
                int16_t play[VC_FRAME_SAMPLES];
                if (pcmring_pop(&vc->out_ring, play) == 0) {
                    Pa_WriteStream(vc->out_stream, play, VC_FRAME_SAMPLES);
                }
            }
            continue;
        }

        /* Video fragment */
        if (pkt_type == PKT_TYPE_VIDEO_FRAG && vc->video_enabled) {
            size_t frag_len = 0;
            /* Replays are dropped inside, before the reassembler ever sees the
             * fragment: a repeat there would corrupt a frame. */
            if (decrypt_from_sender(vc, rbuf, (size_t)n, MK_STREAM_VIDEO,
                                    dec_buf, VC_MAX_VP8_FRAME, &frag_len) < 0) {
                continue;
            }

            /* Expire old incomplete frames */
            video_frag_receiver_expire(&vc->frag_recv, video_time_ms());

            uint32_t completed_fid = 0;
            int frame_size = video_frag_receiver_push(&vc->frag_recv,
                                                       dec_buf, (int)frag_len,
                                                       yuv_buf, VC_MAX_VP8_FRAME,
                                                       &completed_fid);
            if (frame_size > 0) {
                /* Decode VP8 frame */
                int dec_w = 0, dec_h = 0;
                uint8_t *yuv_dec = (uint8_t *)malloc(VC_MAX_YUV_FRAME);
                if (yuv_dec) {
                    int yuv_size = video_decoder_decode(vc->v_dec, yuv_buf, frame_size,
                                                        yuv_dec, VC_MAX_YUV_FRAME,
                                                        &dec_w, &dec_h);
                    if (yuv_size > 0 && dec_w > 0 && dec_h > 0) {
                        /* Pass to display thread */
#ifdef _WIN32
                        EnterCriticalSection(&vc->disp_lock);
#else
                        pthread_mutex_lock(&vc->disp_lock);
#endif
                        if (!vc->disp_yuv || vc->disp_width != dec_w || vc->disp_height != dec_h) {
                            free(vc->disp_yuv);
                            vc->disp_yuv = (uint8_t *)malloc(yuv_size);
                            vc->disp_width = dec_w;
                            vc->disp_height = dec_h;
                        }
                        if (vc->disp_yuv) {
                            memcpy(vc->disp_yuv, yuv_dec, yuv_size);
                            atomic_store(&vc->disp_new_frame, 1);
                        }
#ifdef _WIN32
                        LeaveCriticalSection(&vc->disp_lock);
#else
                        pthread_mutex_unlock(&vc->disp_lock);
#endif
                    }
                    free(yuv_dec);
                }
            }
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
                if (sp.rtt_ms != 0) {
                    uint32_t now32 = (uint32_t)(video_time_ms() & 0xFFFFFFFF);
                    vc->measured_rtt_ms = now32 - sp.rtt_ms;
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
#ifdef _WIN32
            EnterCriticalSection(&vc->disp_lock);
#else
            pthread_mutex_lock(&vc->disp_lock);
#endif
            if (vc->disp_yuv) {
                video_display_render_pip(vc->display,
                                         vc->disp_yuv, vc->disp_width, vc->disp_height,
                                         vc->local_yuv, vc->local_width, vc->local_height);
            }
            atomic_store(&vc->disp_new_frame, 0);
#ifdef _WIN32
            LeaveCriticalSection(&vc->disp_lock);
#else
            pthread_mutex_unlock(&vc->disp_lock);
#endif
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

    vc->dec = opus_decoder_create(VC_SAMPLE_RATE, VC_CHANNELS, &err);
    if (!vc->dec || err != OPUS_OK) return -1;

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
#else
    if (vc->th_vsend) { pthread_join(vc->th_vsend, NULL); vc->th_vsend = 0; }
    if (vc->th_asend) { pthread_join(vc->th_asend, NULL); vc->th_asend = 0; }
    if (vc->th_recv)  { pthread_join(vc->th_recv, NULL);  vc->th_recv = 0; }
#endif

    if (vc->in_stream) { Pa_StopStream(vc->in_stream); Pa_CloseStream(vc->in_stream); }
    if (vc->out_stream) { Pa_StopStream(vc->out_stream); Pa_CloseStream(vc->out_stream); }
    Pa_Terminate();

    if (vc->enc) opus_encoder_destroy(vc->enc);
    if (vc->dec) opus_decoder_destroy(vc->dec);

    video_capture_close(vc->capture);
    video_encoder_close(vc->v_enc);
    video_decoder_close(vc->v_dec);
    if (vc->display) { video_display_close(vc->display); vc->display = NULL; }

    video_frag_receiver_free(&vc->frag_recv);
    pcmring_free(&vc->out_ring);

    if (vc->tcp_sock) CLOSESOCK(vc->tcp_sock);
    if (vc->sock) CLOSESOCK(vc->sock);
    free(vc->disp_yuv);
    free(vc->local_yuv);

#ifdef _WIN32
    DeleteCriticalSection(&vc->disp_lock);
    if (vc->tcp_sock) DeleteCriticalSection(&vc->tcp_send_lock);
#else
    pthread_mutex_destroy(&vc->disp_lock);
    if (vc->relay_mode) pthread_mutex_destroy(&vc->tcp_send_lock);
#endif

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

    /* Ring buffer */
    if (pcmring_init(&vc->out_ring, PCM_RING_CAPACITY) != 0) {
        free(vc); SDL_Quit(); return -1;
    }

    /* Fragment receiver */
    video_frag_receiver_init(&vc->frag_recv);

    /* Socket */
    vc->sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (vc->sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "socket() failed\n");
        pcmring_free(&vc->out_ring); free(vc); SDL_Quit(); return -1;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(opts->local_port);
    if (bind(vc->sock, (struct sockaddr *)&local, sizeof(local)) == SOCK_ERR) {
        fprintf(stderr, "bind() failed (port %u)\n", opts->local_port);
        CLOSESOCK(vc->sock); pcmring_free(&vc->out_ring); free(vc); SDL_Quit(); return -1;
    }

    vc->peer_set = 0;
    vc->relay_mode = 0;
    if (remote_ip && remote_port != 0) {
        memset(&vc->peer, 0, sizeof(vc->peer));
        vc->peer.sin_family = AF_INET;
        vc->peer.sin_port = htons(remote_port);
        if (resolve_host_v4(remote_ip, &vc->peer.sin_addr) != 0) {
            fprintf(stderr, "cannot resolve host %s\n", remote_ip);
            CLOSESOCK(vc->sock); pcmring_free(&vc->out_ring); free(vc); SDL_Quit(); return -1;
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
                CLOSESOCK(vc->sock); pcmring_free(&vc->out_ring); free(vc); SDL_Quit(); return -1;
            }
            if (tcp_relay_register(vc) != 0) {
                fprintf(stderr, "TCP relay registration failed\n");
                CLOSESOCK(vc->tcp_sock); CLOSESOCK(vc->sock);
                pcmring_free(&vc->out_ring); free(vc); SDL_Quit(); return -1;
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

        if (video_decoder_open(&vc->v_dec) != 0) {
            fprintf(stderr, "Warning: VP8 decoder failed\n");
            vc->v_dec = NULL;
        }
    }

    /* Send initial HELLO */
    if (vc->peer_set) send_hello(vc);

    /* Start threads (recv, asend, vsend) */
    ThreadArgs *a1 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs)); a1->vc = vc;
    ThreadArgs *a2 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs)); a2->vc = vc;
    ThreadArgs *a3 = (ThreadArgs *)calloc(1, sizeof(ThreadArgs)); a3->vc = vc;

#ifdef _WIN32
    vc->th_recv  = CreateThread(NULL, 0, th_recv_func, a1, 0, NULL);
    vc->th_asend = CreateThread(NULL, 0, th_asend_func, a2, 0, NULL);
    vc->th_vsend = CreateThread(NULL, 0, th_vsend_func, a3, 0, NULL);
#else
    pthread_create(&vc->th_recv,  NULL, th_recv_func, a1);
    pthread_create(&vc->th_asend, NULL, th_asend_func, a2);
    pthread_create(&vc->th_vsend, NULL, th_vsend_func, a3);
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
    uint64_t last_announce_ms = video_time_ms();
    while (!atomic_load(&g_sigint) && atomic_load(&vc->running)) {
        /* Re-announce until somebody answers. A HELLO2 carries only our own
         * salt, and ms_install is idempotent per salt, so repeating it resets
         * nothing at the peer. This replaces the spin the send threads used to
         * do, which blocked encryption on a handshake it no longer needs. */
        if (atomic_load(&vc->peers_known) == 0 && (vc->peer_set || vc->tcp_sock)) {
            uint64_t now_ms = video_time_ms();
            if (now_ms - last_announce_ms >= HELLO_REANNOUNCE_MS) {
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
#ifdef _WIN32
                EnterCriticalSection(&vc->disp_lock);
#else
                pthread_mutex_lock(&vc->disp_lock);
#endif
                if (vc->disp_yuv) {
                    video_display_render_pip(vc->display,
                                             vc->disp_yuv, vc->disp_width, vc->disp_height,
                                             vc->local_yuv, vc->local_width, vc->local_height);
                }
                atomic_store(&vc->disp_new_frame, 0);
#ifdef _WIN32
                LeaveCriticalSection(&vc->disp_lock);
#else
                pthread_mutex_unlock(&vc->disp_lock);
#endif
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
