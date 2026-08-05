/* audio_call.c
   Самостоятельная консольная программа: защищённые аудиозвонки (PortAudio + Opus + libsodium)
   Поддерживает: Windows (Winsock2) и POSIX (Linux/macOS)
   Сборка (пример):
     Linux:
       gcc audio_call.c -o audio_call -lportaudio -lopus -lsodium -lpthread
     Windows (MinGW):
       gcc audio_call.c -o audio_call.exe -lportaudio -lopus -lsodium -lws2_32
   Нововведение: добавлен режим hub (ретранслятор):
     audio_call hub <bind_port>
   Остальные команды:
     audio_call genkey
     audio_call call <remote_ip> <remote_port> <hexkey32> [local_bind_port]
     audio_call listen <local_bind_port> <hexkey32>
*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#  define CLOSESOCK closesocket
#  define SOCK_ERR SOCKET_ERROR
#  define THREAD_RET DWORD WINAPI
#  include <windows.h>
#  include <io.h>
#  define isatty _isatty
#  define fileno _fileno
#else
#  include <unistd.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <netinet/tcp.h>
#  include <netdb.h>
#  include <pthread.h>
#  include <sys/select.h>
typedef int socket_t;
#  define CLOSESOCK close
#  define SOCK_ERR -1
#  define THREAD_RET void*
#endif

/* Если у вас нет PortAudio/Opus/libsodium при сборке только хаба,
   компиляция все равно потребует этих заголовков из-за единого файла.
   Но hub не использует PortAudio/Opus во время выполнения. */
#include <opus.h>
#include <sodium.h>
#include <portaudio.h>

/* Модульные компоненты */
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
#include "identity.h"
#include "mic_dsp.h"

/* -------------------------- Конфигурация --------------------------------- */

#define AC_SAMPLE_RATE       48000
#define AC_CHANNELS          1
#define AC_FRAME_MS          20
#define AC_FRAME_SAMPLES     ((AC_SAMPLE_RATE/1000)*AC_FRAME_MS) /* 960 */
#define AC_APP               OPUS_APPLICATION_VOIP
#define AC_OPUS_BITRATE      128000  /* 128 kbps for high quality */
#define AC_OPUS_COMPLEXITY   5
#define AC_UDP_RECV_BUFSZ    1500

/* Replay protection now lives in the sender table (identity/media_senders.h):
 * one sliding window per participant and per counter domain, keyed by the
 * salt that participant announced. The two windows that used to sit here
 * could only ever track one peer, so in a call with three people they
 * tracked whoever spoke last. */

/* Per-call identifier from --call-id. Mandatory: it is mixed into every
 * media key, so the same room key used for two calls never produces the same
 * key stream and a recording cannot be replayed into a later call. Every
 * participant must be handed the same value or their keys will not match. */
static uint8_t g_call_id[MK_CALLID_BYTES];
static int g_have_call_id = 0;

#define AC_MAX_OPUS_BYTES    1275
#define AC_PCM_BYTES_PER_FR  (AC_FRAME_SAMPLES * sizeof(int16_t) * AC_CHANNELS)

/* Пакеты протокола. Значения байта типа не меняются. HELLO теперь приходит
   с типом MH_TYPE (0x7E); старый 0x7F распознаётся только для того, чтобы
   сказать пользователю, что у собеседника сборка без групповых звонков. */
#define PKT_VER_AUDIO  0x01
#define PKT_VER_STATS  0x04

/* key_version under which this build derives every media key. Nothing
   produces a nonzero generation yet, and desktop and Android must agree. */
#define AC_KEY_VERSION 0

/* How often to repeat our HELLO2 while nobody has answered us (ms). */
#define AC_HELLO_RETRY_MS 1000

/* ...and how often once somebody has. A repeat costs one small packet and is
   a no-op at every peer that already installed us, but it is the only way a
   peer whose own single reply was lost can still learn our salt. */
#define AC_HELLO_KEEPALIVE_MS 5000

/* An RTT above this is somebody else's clock arriving in the echo, not a
 * round trip. See where it is used. */
#define AC_RTT_SANE_MAX_MS 5000

/* Stats exchange interval (ms) */
#define AC_STATS_INTERVAL_MS 2000

/* AES-GCM конфигурация. Ключ звонка ровно той же длины, что и выводимые из
   него ключи отправителей: AES_GCM_KEY_LEN == MK_KEY_BYTES == 32.
   Nonce и тег целиком собираются в identity/media_packet.c, здесь их нет:
   4-байтовый префикс nonce, который передавался в HELLO, удалён вместе со
   всей схемой "один ключ на звонок". */
#define AES_GCM_KEY_LEN   crypto_aead_aes256gcm_KEYBYTES   /* 32 байта */

/* Небольшая задержка */
#define PLAYOUT_BUFFER_FRAMES 6

/* How many participants are rendered at once.
 *
 * The key table holds 32 senders because the transport does, but decoding
 * and mixing 32 streams is not something a phone will do, and a room where
 * eight people talk at once is already unusable for human reasons. Senders
 * beyond this are still authenticated and still tracked - they simply are
 * not rendered, and the least recently heard one gives up its decoder when
 * somebody new speaks. */
#define AC_MAX_MIX 8

/* Хаб: параметры */
#define HUB_MAX_CLIENTS 1024
#define HUB_CLIENT_TIMEOUT_SEC 60

/* ------------------------- Вспомогательные -------------------------------- */

/* Сетевые функции теперь в audio_network.h:
   - htonll_u64(uint64_t v)
   - ntohll_u64(uint64_t v)
   - msleep(unsigned ms)
   - net_init_once(void)
*/

/* --------------------- Кольцевой буфер PCM ------------------------------- */

/* PcmRing теперь в audio_ring.h:
   - typedef struct PcmRing
   - pcmring_init(PcmRing *r, size_t frames_cap)
   - pcmring_free(PcmRing *r)
   - pcmring_push(PcmRing *r, const int16_t *frame)
   - pcmring_pop(PcmRing *r, int16_t *out_frame)
*/

/* --------------------------- Состояние звонка ---------------------------- */

/* The HELLO2 wire format - flags, sizes, MAC and signature - belongs to
   identity/media_hello.c, so nothing about it is defined here any more. */

/**
 * One rendered participant: its decoder, its jitter buffer, and enough
 * bookkeeping to decide who gives up a decoder when a new voice arrives.
 */
typedef struct {
    int          slot;       /**< sender-table slot, or -1 when free */
    OpusDecoder *dec;
    PcmRing      ring;
    uint64_t     last_ms;    /**< when we last decoded a frame from it */
    int          prefilled;  /**< jitter buffer has reached the play-out depth */
    uint64_t     frames;     /**< frames actually mixed, for the teardown report */
} MixSlot;

typedef struct AudioCall {
    socket_t sock;
    struct sockaddr_in peer;
    int peer_set;

    /* Relay mode */
    int relay_mode;
    /* Обработка микрофона: чувствительность и ворота против фона.
     * Состояние живёт весь звонок - оценка фона набирается постепенно. */
    mic_dsp_t mic;
    float     mic_gain_db;
    mic_ns_level_t mic_ns;

    char relay_room[256];
    char relay_name[256];
    socket_t tcp_sock;      /* TCP socket for relay (0 = unused) */
#ifdef _WIN32
    CRITICAL_SECTION tcp_send_lock;
#else
    pthread_mutex_t tcp_send_lock;
#endif

    /* Group-call media keys (identity/media_keys.h). Every field below is
       drawn once in audio_call_start, before any thread exists, and is
       immutable afterwards - which is what lets the send thread encrypt
       without a lock: there is no re-derivation for it to race against. */
    uint8_t master_key[MK_KEY_BYTES];   /**< K_call, the room key from the invite */
    uint8_t call_id[MK_CALLID_BYTES];   /**< binds every key to this one call */
    uint8_t hello_key[MK_KEY_BYTES];    /**< mk_hello_key(K_call, call_id) */
    uint8_t own_salt[MK_SALT_BYTES];    /**< our announcement; never re-drawn */
    uint8_t own_sid[MK_SID_BYTES];      /**< our tag on the wire */
    uint8_t idbind[MK_IDBIND_BYTES];    /**< our Ed25519 pk, or 32 zero bytes */
    /* One counter domain in this binary: audio frames and stats both draw
       from seq_tx, so they share this key. Two packet types on one counter
       are safe because the counter never repeats; a second counter would
       need a second stream id. */
    uint8_t send_key_audio[MK_KEY_BYTES];

    /* Receive side: a key slot and a replay window per participant. Touched
       only by the receive thread, so it needs no lock. */
    ms_table_t senders;
    /* Packets successfully decrypted from each slot. Only the teardown
     * report uses it, and that report is what the three-party loopback test
     * asserts on: without a count there is no way to tell "installed a
     * peer" apart from "actually heard that peer". */
    uint64_t rx_count[MS_MAX_SLOTS];
    atomic_int have_peer;        /**< set once any peer has been installed */
    int legacy_peer_warned;      /**< an old peer is reported once, not per packet */
    int foreign_call_warned;     /**< likewise for a HELLO of another call */
    int install_warned;          /**< likewise for a table that cannot take a peer */

    atomic_uint_fast64_t seq_tx; /**< transmit counter, shared by audio and stats */

    PaStream *in_stream;
    PaStream *out_stream;
    OpusEncoder *enc;

    /* One decoder and one jitter buffer per rendered participant.
     *
     * A single decoder cannot serve several senders: Opus carries state
     * across frames, so interleaving two streams through one decoder makes
     * both unintelligible - and a single output buffer would have them
     * overwrite each other rather than mix. That is why the crypto working
     * for N participants is not the same as the call working for N: this is
     * the other half. */
    MixSlot mix[AC_MAX_MIX];
    int mix_ready;   /**< rings and lock exist; teardown is a no-op without it */
#ifdef _WIN32
    CRITICAL_SECTION mix_lock;
#else
    pthread_mutex_t mix_lock;
#endif

    /* RTT measurement (ping/pong via stats packets) */
    uint32_t last_peer_ping_ts;            /* peer's timestamp to echo back */
    uint64_t peer_ping_recv_time;          /* when we received the peer's ping */
    uint32_t measured_rtt_ms;              /* our measured round-trip time */
    uint64_t last_stats_time_ms;           /* last time we sent stats */

    /* Identity signing (optional) */
    int has_identity;
    uint8_t identity_pk[IDENTITY_PK_BYTES];
    uint8_t identity_sk[IDENTITY_SK_BYTES];
    uint8_t peer_identity_pk[IDENTITY_PK_BYTES];
    int peer_verified;           /* 0=unknown, 1=verified, -1=conflict */
    char known_keys_path[512];

#ifdef _WIN32
    HANDLE th_send;
    HANDLE th_recv;
    HANDLE th_play;
#else
    pthread_t th_send;
    pthread_t th_recv;
    pthread_t th_play;
#endif
    atomic_int running;
} AudioCall;

/* --------------------------- Сеть: инициализация ------------------------- */

/* net_init_once() теперь в audio_network.h */

/* ------------------------- HELLO handshake -------------------------------- */

/* Forward declaration (defined after TCP relay helpers) */
static int ac_send_packet(AudioCall *c, const uint8_t *data, int len);

/**
 * Announce ourselves with one HELLO2: this call's id, our own salt and,
 * when an identity is loaded, our signed public key. That is everything a
 * peer needs to derive the key we encrypt with - there is nothing to
 * negotiate and no reply to wait for.
 *
 * Only immutable state is read here, so both threads may call it.
 */
static int send_hello(AudioCall *c) {
    mh_hello_t h;
    memset(&h, 0, sizeof h);
    /* This binary sends audio only. Width, height and fps stay zero because
       MH_FLAG_VIDEO is not set. */
    h.flags = MH_FLAG_AUDIO;
    if (c->has_identity) h.flags |= MH_FLAG_IDENTITY;
    h.key_version = AC_KEY_VERSION;

    /* Same label the video path announces: a name under a voice is worth as
     * much as a name under a picture. */
    snprintf(h.name, sizeof h.name, "%.*s",
             (int)(sizeof h.name - 1), c->relay_name);
    memcpy(h.call_id, c->call_id, MK_CALLID_BYTES);
    memcpy(h.sender_salt, c->own_salt, MK_SALT_BYTES);

    uint8_t pkt[MH_SIZE_SIGNED];
    size_t pkt_len = 0;
    mh_status_t st = mh_build(&h, c->hello_key,
                              c->has_identity ? c->identity_sk : NULL,
                              pkt, sizeof pkt, &pkt_len);
    if (st != MH_OK) {
        fprintf(stderr, "[hello] cannot build HELLO: %s\n", mh_strerror(st));
        return -1;
    }
    int rc = ac_send_packet(c, pkt, (int)pkt_len);
    sodium_memzero(pkt, sizeof pkt);
    return rc;
}

/** Why the sender table refused a peer, for a log line the user can act on. */
static const char *ms_reason(ms_status_t s) {
    switch (s) {
        case MS_ERR_FULL:    return "the call is full";
        case MS_ERR_SID_CAP: return "too many participants share this sender tag";
        case MS_ERR_ARGS:    return "the announcement is malformed";
        default:             return "unknown error";
    }
}

/**
 * Trust-on-first-use for one participant, filed under its own public key.
 *
 * The pre-group code filed every peer under the literal name "peer", so with
 * more than two people in a call each new participant looked like the same
 * peer changing its key.
 */
static void ac_tofu_report(AudioCall *c, const uint8_t peer_pk[IDENTITY_PK_BYTES]) {
    char fp[IDENTITY_FINGERPRINT_LEN];
    identity_pk_fingerprint(peer_pk, fp);
    tofu_result_t tofu = identity_tofu_check(c->known_keys_path, fp, peer_pk);
    if (tofu == TOFU_NEW_KEY) {
        printf("[TOFU] New participant identity: %s\n", fp);
        c->peer_verified = 1;
    } else if (tofu == TOFU_KEY_MATCH || tofu == TOFU_KEY_MATCH_VERIFIED) {
        printf("[VERIFIED] Participant identity: %s\n", fp);
        c->peer_verified = 1;
    } else {
        printf("[WARNING] PARTICIPANT KEY CHANGED! Fingerprint: %s\n", fp);
        c->peer_verified = -1;
    }
    memcpy(c->peer_identity_pk, peer_pk, IDENTITY_PK_BYTES);
    fflush(stdout);
}

/**
 * Handle an arriving HELLO2.
 *
 * Called only from the receive thread, which is also the only thread that
 * reads or writes the sender table.
 */
static void handle_hello(AudioCall *c, const uint8_t *buf, size_t len) {
    mh_hello_t h;
    mh_status_t st = mh_parse(buf, len, c->hello_key, &h);
    if (st != MH_OK) {
        if (st == MH_ERR_LEGACY_PEER && !c->legacy_peer_warned) {
            c->legacy_peer_warned = 1;
            printf("[!] A peer is running a pre-group build of F.E.A.R. and cannot be "
                   "heard: it has to be updated.\n");
            fflush(stdout);
        }
        /* Never answer a HELLO that failed to parse. The old code replied to
           anything shaped like one, which told an off-path prober whether it
           had guessed the room key and let a single packet start an
           unbounded exchange. */
        return;
    }

    /* The MAC already binds the call, but a room member could still announce
       a different call_id in the body: its keys would then hang off a value
       we do not have and nothing it sends would ever decrypt. Say so once
       rather than dropping its media in silence. */
    if (memcmp(h.call_id, c->call_id, MK_CALLID_BYTES) != 0) {
        if (!c->foreign_call_warned) {
            c->foreign_call_warned = 1;
            printf("[!] Ignoring a HELLO that announces a different call id.\n");
            fflush(stdout);
        }
        return;
    }

    /* An unsigned participant binds 32 zero bytes, exactly as it did when it
       derived its own send key. */
    uint8_t idbind[MK_IDBIND_BYTES];
    memset(idbind, 0, sizeof idbind);
    if (h.flags & MH_FLAG_IDENTITY) memcpy(idbind, h.pk, MH_PK_BYTES);

    /* Installing the same announcement twice is a no-op by construction, so
       a repeated (or replayed) HELLO cannot reset anybody's replay window. */
    const int before = ms_count(&c->senders);
    int idx = -1;
    ms_status_t ss = ms_install(&c->senders, h.sender_salt, idbind,
                                h.key_version, &idx);
    if (ss != MS_OK) {
        /* MS_ERR_SELF is our own announcement coming back off the relay and
           is entirely normal. The rest mean we cannot hear this peer. */
        if (ss != MS_ERR_SELF && !c->install_warned) {
            c->install_warned = 1;
            printf("[!] Cannot add a participant: %s\n", ms_reason(ss));
            fflush(stdout);
        }
        return;
    }
    if (ms_count(&c->senders) == before) return;  /* already installed */

    atomic_store(&c->have_peer, 1);
    if (h.flags & MH_FLAG_IDENTITY) {
        ac_tofu_report(c, h.pk);
    } else {
        printf("[hello] New participant (unsigned); %d now in call\n",
               ms_count(&c->senders));
        fflush(stdout);
    }

    /* Exactly one reply, and only for a participant we had not seen before,
       so the newcomer learns our salt without a HELLO storm when several
       people join at once. */
    if (c->peer_set || c->tcp_sock) send_hello(c);
}

/* ===== UDP relay registration ===== */

static int send_udp_registration(AudioCall *c) {
    /* Packet: [0xFE][2 room_len LE][room][2 name_len LE][name] */
    uint16_t room_len = (uint16_t)strlen(c->relay_room);
    uint16_t name_len = (uint16_t)strlen(c->relay_name);
    size_t pkt_len = 1 + 2 + room_len + 2 + name_len;
    uint8_t pkt[1 + 2 + 256 + 2 + 256];

    pkt[0] = 0xFE;
    pkt[1] = (uint8_t)(room_len & 0xFF);
    pkt[2] = (uint8_t)((room_len >> 8) & 0xFF);
    memcpy(pkt + 3, c->relay_room, room_len);
    pkt[3 + room_len] = (uint8_t)(name_len & 0xFF);
    pkt[3 + room_len + 1] = (uint8_t)((name_len >> 8) & 0xFF);
    memcpy(pkt + 3 + room_len + 2, c->relay_name, name_len);

    int r = sendto(c->sock, (const char *)pkt, (int)pkt_len, 0,
                   (struct sockaddr *)&c->peer, sizeof(c->peer));
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

/**
 * Read exactly `len` bytes, treating a receive timeout as "not yet" rather
 * than as a failure.
 *
 * The socket carries a 200 ms timeout so the thread can notice the call
 * ending. Without this distinction every quiet moment would look like a
 * dropped connection and tear the call down.
 */
static int tcp_recv_all(AudioCall *c, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        int n = recv(c->tcp_sock, (char *)(p + got), (int)(len - got), 0);
        if (n > 0) { got += (size_t)n; continue; }
        if (n == 0) return -1;   /* peer closed */
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
#endif
            /* Nothing arrived within the window. Keep waiting unless the
             * call is shutting down, in which case unwind so the thread can
             * exit and teardown can run. */
            if (!atomic_load(&c->running)) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

static int tcp_relay_connect(AudioCall *c, const char *ip, uint16_t port) {
    c->tcp_sock = (socket_t)socket(AF_INET, SOCK_STREAM, 0);
    if (c->tcp_sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "TCP socket() failed\n");
        return -1;
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if (resolve_host_v4(ip, &srv.sin_addr) != 0) {
        fprintf(stderr, "TCP relay: cannot resolve host %s\n", ip);
        CLOSESOCK(c->tcp_sock); c->tcp_sock = 0;
        return -1;
    }
    /* Same reason as the UDP socket: without a timeout the receive thread
     * sits in recv() until a packet arrives, audio_call_stop blocks in
     * pthread_join, and Ctrl+C never finishes - so the teardown, including
     * the key wiping, never runs. The UDP path was fixed earlier; a relay
     * call goes through this socket instead, and phones use relay, so this
     * is the path that matters most in practice.
     *
     * tcp_recv_all below tells a timeout apart from a broken connection, so
     * a quiet call is not mistaken for a dropped one. */
    {
#ifdef _WIN32
        DWORD rcv_to = 200;
        setsockopt(c->tcp_sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&rcv_to, sizeof rcv_to);
#else
        struct timeval rcv_to;
        rcv_to.tv_sec = 0;
        rcv_to.tv_usec = 200000;
        setsockopt(c->tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof rcv_to);
#endif
    }

    if (connect(c->tcp_sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        fprintf(stderr, "TCP connect failed to %s:%u\n", ip, port);
        CLOSESOCK(c->tcp_sock); c->tcp_sock = 0;
        return -1;
    }
    /* Disable Nagle's algorithm for low-latency media relay */
    int flag = 1;
    setsockopt(c->tcp_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
    printf("TCP relay connected to %s:%u\n", ip, port);
    return 0;
}

static int tcp_relay_register(AudioCall *c) {
    uint16_t room_len = (uint16_t)strlen(c->relay_room);
    uint16_t name_len = (uint16_t)strlen(c->relay_name);
    size_t frame_len = 2 + room_len + 2 + name_len + 2 + TCP_NONCE_LEN + 1 + 4 + 1;
    uint8_t *frame = (uint8_t *)calloc(1, frame_len);
    if (!frame) return -1;

    uint8_t *w = frame;
    w[0] = room_len & 0xFF; w[1] = (room_len >> 8) & 0xFF; w += 2;
    memcpy(w, c->relay_room, room_len); w += room_len;
    w[0] = name_len & 0xFF; w[1] = (name_len >> 8) & 0xFF; w += 2;
    memcpy(w, c->relay_name, name_len); w += name_len;
    w[0] = TCP_NONCE_LEN; w[1] = 0; w += 2;
    memset(w, 0, TCP_NONCE_LEN); w += TCP_NONCE_LEN;
    *w++ = MSG_TYPE_MEDIA_RELAY; /* media relay registration */
    w[0] = 1; w[1] = 0; w[2] = 0; w[3] = 0; w += 4;
    *w++ = 0;

    int ret = tcp_send_all(c->tcp_sock, frame, frame_len);
    free(frame);
    if (ret == 0) printf("TCP relay registered: room=%s name=%s\n",
                         c->relay_room, c->relay_name);
    return ret;
}

static int tcp_relay_send_media(AudioCall *c, const uint8_t *media, int media_len) {
    uint16_t room_len = (uint16_t)strlen(c->relay_room);
    uint16_t name_len = (uint16_t)strlen(c->relay_name);
    size_t frame_len = 2 + room_len + 2 + name_len + 2 + TCP_NONCE_LEN + 1 + 4 + (size_t)media_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) return -1;

    uint8_t *w = frame;
    w[0] = room_len & 0xFF; w[1] = (room_len >> 8) & 0xFF; w += 2;
    memcpy(w, c->relay_room, room_len); w += room_len;
    w[0] = name_len & 0xFF; w[1] = (name_len >> 8) & 0xFF; w += 2;
    memcpy(w, c->relay_name, name_len); w += name_len;
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
    EnterCriticalSection(&c->tcp_send_lock);
#else
    pthread_mutex_lock(&c->tcp_send_lock);
#endif
    int ret = tcp_send_all(c->tcp_sock, frame, frame_len);
#ifdef _WIN32
    LeaveCriticalSection(&c->tcp_send_lock);
#else
    pthread_mutex_unlock(&c->tcp_send_lock);
#endif
    free(frame);
    return ret;
}

static int tcp_relay_recv_media(AudioCall *c, uint8_t *out, int out_size) {
    for (;;) {
        uint8_t hdr2[2];
        uint8_t skip[512];

        if (tcp_recv_all(c, hdr2, 2) < 0) return -1;
        uint16_t room_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (room_len > 255) return -1;
        if (tcp_recv_all(c, skip, room_len) < 0) return -1;

        if (tcp_recv_all(c, hdr2, 2) < 0) return -1;
        uint16_t name_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (name_len > 255) return -1;
        if (tcp_recv_all(c, skip, name_len) < 0) return -1;

        if (tcp_recv_all(c, hdr2, 2) < 0) return -1;
        uint16_t nonce_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (nonce_len > sizeof(skip)) return -1;
        if (nonce_len > 0 && tcp_recv_all(c, skip, nonce_len) < 0) return -1;

        uint8_t type;
        if (tcp_recv_all(c, &type, 1) < 0) return -1;

        uint8_t clenbuf[4];
        if (tcp_recv_all(c, clenbuf, 4) < 0) return -1;
        uint32_t clen = (uint32_t)(clenbuf[0] | (clenbuf[1] << 8) |
                                    (clenbuf[2] << 16) | (clenbuf[3] << 24));

        /* Unsigned comparison. A signed cast here let clen >= 0x80000000 read as
         * negative, pass the bound check and overflow `out` with data from an
         * untrusted relay server (no room key required). */
        if (type == MSG_TYPE_MEDIA_RELAY && clen > 0 &&
            out_size > 0 && clen <= (uint32_t)out_size) {
            if (tcp_recv_all(c, out, clen) < 0) return -1;
            return (int)clen;
        }

        uint32_t remaining = clen;
        while (remaining > 0) {
            uint32_t chunk = remaining > sizeof(skip) ? sizeof(skip) : remaining;
            if (tcp_recv_all(c, skip, chunk) < 0) return -1;
            remaining -= chunk;
        }
    }
}

static int ac_send_packet(AudioCall *c, const uint8_t *data, int len) {
    if (c->relay_mode && c->tcp_sock) {
        return tcp_relay_send_media(c, data, len);
    }
    if (c->peer_set) {
        int r = sendto(c->sock, (const char *)data, len, 0,
                       (struct sockaddr *)&c->peer, sizeof(c->peer));
        return (r > 0) ? 0 : -1;
    }
    return -1;
}

/* --------------------------- AEAD-helpers -------------------------------- */

/* Кадрирование и AEAD теперь в identity/media_packet.c: mp_encrypt / mp_peek
   / mp_decrypt, заголовок [type(1)][SID(3)][counter(5)], он же AAD.
   audio_encrypt_packet()/audio_decrypt_packet() из audio_crypto.h этим
   файлом больше не используются: у них один ключ на весь звонок и префикс
   nonce, выученный из HELLO - ровно то, что ломало групповые звонки. */

/**
 * Encrypt one outgoing packet: our own tag, our own counter, our own key.
 *
 * audio_call keeps a single transmit counter (c->seq_tx) that carries both
 * audio frames and stats, so the two are one counter domain and share the
 * MK_STREAM_AUDIO key. Two packet types on one counter never repeat a nonce;
 * two counters under one key would collide immediately.
 */
/**
 * Release every decoder, jitter buffer and the lock. Safe to call on a
 * half-built call: the object is calloc'd, so mix_ready is what says whether
 * any of this was ever set up.
 */
static void mix_teardown(AudioCall *c) {
    if (!c->mix_ready) return;
    for (int i = 0; i < AC_MAX_MIX; i++) {
        if (c->mix[i].dec) {
            opus_decoder_destroy(c->mix[i].dec);
            c->mix[i].dec = NULL;
        }
        pcmring_free(&c->mix[i].ring);
        c->mix[i].slot = -1;
    }
#ifdef _WIN32
    DeleteCriticalSection(&c->mix_lock);
#else
    pthread_mutex_destroy(&c->mix_lock);
#endif
    c->mix_ready = 0;
}

static void mix_lock_take(AudioCall *c) {
#ifdef _WIN32
    EnterCriticalSection(&c->mix_lock);
#else
    pthread_mutex_lock(&c->mix_lock);
#endif
}

static void mix_lock_drop(AudioCall *c) {
#ifdef _WIN32
    LeaveCriticalSection(&c->mix_lock);
#else
    pthread_mutex_unlock(&c->mix_lock);
#endif
}

/**
 * The decoder and jitter buffer for a sender, creating or reassigning one if
 * this is a voice we are not currently rendering.
 *
 * Reassignment resets the Opus state: the buffer would otherwise carry the
 * previous speaker's history into the new stream and decode it as noise.
 * Returns NULL only if a decoder cannot be created at all.
 */
static MixSlot *mix_acquire(AudioCall *c, int slot) {
    MixSlot *chosen = NULL;

    for (int i = 0; i < AC_MAX_MIX; i++) {
        if (c->mix[i].slot == slot) return &c->mix[i];
    }
    for (int i = 0; i < AC_MAX_MIX; i++) {
        if (c->mix[i].slot < 0) { chosen = &c->mix[i]; break; }
    }
    if (!chosen) {
        /* Everything is busy: the voice heard longest ago steps aside. Its
         * key and replay window survive in the sender table, so it comes
         * back the moment it speaks again. */
        chosen = &c->mix[0];
        for (int i = 1; i < AC_MAX_MIX; i++) {
            if (c->mix[i].last_ms < chosen->last_ms) chosen = &c->mix[i];
        }
        int16_t discard[AC_FRAME_SAMPLES * AC_CHANNELS];
        while (pcmring_pop(&chosen->ring, discard) == 0) { }
        if (chosen->dec) opus_decoder_ctl(chosen->dec, OPUS_RESET_STATE);
    }

    if (!chosen->dec) {
        int err = 0;
        chosen->dec = opus_decoder_create(AC_SAMPLE_RATE, AC_CHANNELS, &err);
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

static int encrypt_media(AudioCall *c, uint8_t type,
                         const uint8_t *plain, size_t plain_len,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         uint64_t counter)
{
    return mp_encrypt(type, c->own_sid, counter, c->send_key_audio,
                      plain, plain_len, out, out_cap, out_len);
}

/* ===== Stats packet: [0x04][SID(3)][counter(5)][AES-GCM(16 payload + 16 tag)] ===== */

typedef struct {
    uint32_t ping_ts;    /* sender's timestamp (lower 32 bits of ms) */
    uint32_t pong_ts;    /* echo of peer's last ping_ts */
    uint32_t reserved1;
    uint32_t reserved2;
} AudioStatsPayload;

/**
 * Authenticate one arriving packet and identify which participant sent it.
 *
 * The order here is the whole point. The SID selects candidate slots - a
 * 3-byte tag really does collide, so there can be two - each candidate's key
 * is tried, and only once one of them authenticates the packet is the
 * counter offered to that slot's replay window. Moving the window before the
 * tag verifies is exactly how one forged packet at a huge counter can
 * silence a real sender for the rest of the call.
 *
 * @return the slot index, or -1 if no key decrypts it or it is not fresh
 */
static int decrypt_media(AudioCall *c, const uint8_t *pkt, size_t pkt_len,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         uint8_t *out_type)
{
    uint8_t sid[MK_SID_BYTES];
    uint64_t counter = 0;
    if (mp_peek(pkt, pkt_len, out_type, sid, &counter) != 0) return -1;

    int cand[MS_SID_CAP];
    const int ncand = ms_find_by_sid(&c->senders, sid, cand);
    for (int i = 0; i < ncand; i++) {
        const uint8_t *k = ms_key(&c->senders, cand[i], MK_STREAM_AUDIO);
        if (!k) continue;
        if (mp_decrypt(pkt, pkt_len, k, out, out_cap, out_len) != 0) continue;
        /* Authenticated. Only now may this packet touch the window. */
        if (ms_accept_seq(&c->senders, cand[i], MK_STREAM_AUDIO, counter) != MS_FRESH) {
            return -1;   /* replayed, older than the window, or a forged jump */
        }
        if (cand[i] >= 0 && cand[i] < MS_MAX_SLOTS) c->rx_count[cand[i]]++;
        return cand[i];
    }
    return -1;
}

static uint64_t audio_time_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

/* ----------------------------- Потоки ----------------------------------- */

typedef struct {
    AudioCall *c;
} ThreadArgs;

static THREAD_RET th_send_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs*)arg;
    AudioCall *c = ta->c;
    free(ta);

    /* Nothing to wait for. Our key comes from our own salt, so we can
       encrypt from the very first frame. The old build spun here until a
       peer's nonce prefix arrived - the same cached prefix that made a
       third participant impossible. */
    int16_t pcm[AC_FRAME_SAMPLES];
    uint8_t opus[AC_MAX_OPUS_BYTES];
    uint8_t packet[MP_HEADER_BYTES + AC_MAX_OPUS_BYTES + MP_TAG_BYTES];

    if (c->peer_set || c->tcp_sock) send_hello(c);
    uint64_t last_hello_ms = audio_time_ms();
    c->last_stats_time_ms = audio_time_ms();

    while (atomic_load(&c->running)) {
        if (c->in_stream == NULL) {
            memset(pcm, 0, sizeof(pcm));
        } else {
            PaError pe = Pa_ReadStream(c->in_stream, pcm, AC_FRAME_SAMPLES);
            if (pe == paInputOverflowed) {
                continue;
            } else if (pe != paNoError) {
                msleep(2);
                continue;
            }
        }

        /* Между микрофоном и кодировщиком: срез низов, ворота против фона
         * и чувствительность. Именно здесь, а не после кодирования, -
         * кодировщику достаётся уже то, что услышит собеседник. */
        mic_dsp_process(&c->mic, pcm, AC_FRAME_SAMPLES);

        int enc_bytes = opus_encode(c->enc, pcm, AC_FRAME_SAMPLES, opus, (opus_int32)sizeof(opus));
        if (enc_bytes < 0) {
            continue;
        }

        uint64_t seq = atomic_fetch_add(&c->seq_tx, 1);
        size_t pkt_len = 0;
        if (encrypt_media(c, PKT_VER_AUDIO, opus, (size_t)enc_bytes,
                          packet, sizeof packet, &pkt_len, seq) != 0) {
            continue;
        }

        ac_send_packet(c, packet, (int)pkt_len);

        uint64_t now = audio_time_ms();

        /* Re-announce ourselves: quickly while nobody has answered, because
           the first HELLO is simply lost if the other side is not up yet,
           and slowly afterwards, because a peer whose single reply to us was
           dropped has no other way to hear our salt. A repeat installs
           nothing new and draws no reply, so this cannot turn into a
           handshake storm. */
        const uint64_t hello_gap = atomic_load(&c->have_peer)
                                       ? AC_HELLO_KEEPALIVE_MS
                                       : AC_HELLO_RETRY_MS;
        if ((c->peer_set || c->tcp_sock) && (now - last_hello_ms) >= hello_gap) {
            last_hello_ms = now;
            /* Re-send UDP relay registration periodically (only for UDP relay) */
            if (c->relay_mode && !c->tcp_sock) send_udp_registration(c);
            send_hello(c);
        }

        /* Send stats every 2 seconds */
        if ((now - c->last_stats_time_ms) >= AC_STATS_INTERVAL_MS) {
            c->last_stats_time_ms = now;

            AudioStatsPayload sp;
            memset(&sp, 0, sizeof(sp));
            sp.ping_ts = (uint32_t)(now & 0xFFFFFFFF);
            {
                uint32_t hold_time = (c->peer_ping_recv_time > 0)
                    ? (uint32_t)(now - c->peer_ping_recv_time) : 0;
                sp.pong_ts = c->last_peer_ping_ts + hold_time;
            }

            uint8_t stats_pkt[MP_HEADER_BYTES + sizeof(AudioStatsPayload) + MP_TAG_BYTES];
            size_t stats_len = 0;
            /* The same counter as the audio frames above, deliberately: one
               counter domain, one key, and the counter never repeats. */
            uint64_t stats_seq = atomic_fetch_add(&c->seq_tx, 1);
            if (encrypt_media(c, PKT_VER_STATS, (const uint8_t *)&sp, sizeof sp,
                              stats_pkt, sizeof stats_pkt, &stats_len, stats_seq) == 0) {
                ac_send_packet(c, stats_pkt, (int)stats_len);
            }

            printf("[STATS] RTT=%u\n", c->measured_rtt_ms);
            fflush(stdout);
        }
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/**
 * Play-out: mix every rendered participant into one stream.
 *
 * This runs on its own thread rather than inside the receive loop, because
 * with several senders the receive loop fires several times per frame period
 * and would push the device far faster than real time. Pa_WriteStream blocks
 * until the device has room, so writing one frame per iteration is what
 * paces this thread - including the silent frames, which keep the device fed
 * while nobody is speaking.
 */
/* Defined below, next to the other teardown helpers; declared here because
 * the media-key setup path frees a half-built call on failure. */
static void ac_free_wiped(AudioCall *c);

static THREAD_RET th_play_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs*)arg;
    AudioCall *c = ta->c;
    free(ta);

    const size_t nsamp = AC_FRAME_SAMPLES * AC_CHANNELS;
    int32_t acc[AC_FRAME_SAMPLES * AC_CHANNELS];
    int16_t frame[AC_FRAME_SAMPLES * AC_CHANNELS];
    int16_t play[AC_FRAME_SAMPLES * AC_CHANNELS];

    while (atomic_load(&c->running)) {
        memset(acc, 0, sizeof acc);

        mix_lock_take(c);
        for (int i = 0; i < AC_MAX_MIX; i++) {
            MixSlot *m = &c->mix[i];
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
        mix_lock_drop(c);

        if (!c->out_stream) {
            /* No output device: still drain at roughly real time so the
             * jitter buffers cannot grow without bound. */
            msleep(20);
            continue;
        }

        /* Saturate rather than wrap. Wrapping turns two loud speakers into a
         * full-scale square wave, which is unpleasant in a way that clipping
         * is not. */
        for (size_t k = 0; k < nsamp; k++) {
            int32_t v = acc[k];
            if (v > 32767) v = 32767;
            else if (v < -32768) v = -32768;
            play[k] = (int16_t)v;
        }
        Pa_WriteStream(c->out_stream, play, AC_FRAME_SAMPLES);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static THREAD_RET th_recv_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs*)arg;
    AudioCall *c = ta->c;
    free(ta);

    uint8_t rbuf[AC_UDP_RECV_BUFSZ];
    /* Decrypted payload: an Opus frame, or a stats struct. */
    uint8_t plain[AC_MAX_OPUS_BYTES];
    int16_t pcm[AC_FRAME_SAMPLES];

    while (atomic_load(&c->running)) {
        int n;

        if (c->relay_mode && c->tcp_sock) {
            /* TCP relay: read media frame from server */
            n = tcp_relay_recv_media(c, rbuf, (int)sizeof(rbuf));
            if (n < 0) {
                fprintf(stderr, "[relay] TCP connection lost\n");
                atomic_store(&c->running, 0);
                break;
            }
            if (n == 0) continue;
        } else {
            struct sockaddr_in src;
#ifdef _WIN32
            int slen = sizeof(src);
#else
            socklen_t slen = sizeof(src);
#endif
            n = recvfrom(c->sock, (char*)rbuf, (int)sizeof(rbuf), 0,
                         (struct sockaddr*)&src, &slen);
            if (n <= 0) {
                msleep(2);
                continue;
            }
            if (!c->peer_set && !c->relay_mode) {
                c->peer = src;
                c->peer_set = 1;
            }
        }

        /* HELLO2, or the pre-group HELLO kept only so an old peer can be
           named as such. Replies happen inside handle_hello and only for a
           peer that is genuinely new. */
        if (n >= 1 && (rbuf[0] == MH_TYPE || rbuf[0] == MH_LEGACY_TYPE)) {
            handle_hello(c, rbuf, (size_t)n);
            continue;
        }

        /* Media: SID -> candidate keys -> AEAD -> replay window, in that
           order and no other (see decrypt_media). */
        uint8_t ptype = 0;
        size_t plain_len = 0;
        int slot = decrypt_media(c, rbuf, (size_t)n, plain, sizeof plain,
                                 &plain_len, &ptype);
        if (slot < 0) continue;

        /* Stats packet: RTT ping/pong. The type byte is authenticated as
           associated data, so it can no longer be flipped between audio and
           stats to route a plaintext to the wrong parser. */
        if (ptype == PKT_VER_STATS) {
            AudioStatsPayload sp;
            if (plain_len < sizeof sp) continue;
            memcpy(&sp, plain, sizeof sp);
            /* Same broadcast echo as the video path, same failure: in a
             * group call most echoes carry a third machine's clock, and the
             * subtraction produces the gap between two uptimes rather than a
             * round trip. Only a plausible value can be one of ours. */
            if (sp.pong_ts != 0) {
                uint32_t now32 = (uint32_t)(audio_time_ms() & 0xFFFFFFFF);
                uint32_t rtt = now32 - sp.pong_ts;
                if (rtt <= AC_RTT_SANE_MAX_MS) c->measured_rtt_ms = rtt;
            }
            c->last_peer_ping_ts = sp.ping_ts;
            c->peer_ping_recv_time = audio_time_ms();
            continue;
        }
        if (ptype != PKT_VER_AUDIO) continue;

        /* Decode into this sender's own decoder. Opus keeps state between
           frames, so one decoder shared by several senders would garble all
           of them - which is why a call whose packets all decrypt correctly
           can still be unintelligible. */
        mix_lock_take(c);
        MixSlot *m = mix_acquire(c, slot);
        if (!m) { mix_lock_drop(c); continue; }

        int dec_samples = opus_decode(m->dec, plain, (opus_int32)plain_len,
                                      pcm, AC_FRAME_SAMPLES, 0);
        if (dec_samples > 0) {
            if (dec_samples < AC_FRAME_SAMPLES) {
                memset(pcm + dec_samples * AC_CHANNELS, 0,
                       (AC_FRAME_SAMPLES - dec_samples) * AC_CHANNELS * sizeof(int16_t));
            }
            pcmring_push(&m->ring, pcm);
            m->last_ms = audio_time_ms();

            /* Latency control per sender: a relay burst must not turn into
               half a second of delay that never drains. */
            #define MAX_PLAYOUT_FRAMES 20
            while (atomic_load(&m->ring.count) > MAX_PLAYOUT_FRAMES) {
                int16_t discard[AC_FRAME_SAMPLES * AC_CHANNELS];
                pcmring_pop(&m->ring, discard);
            }
        }
        mix_lock_drop(c);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ------------------------------ Инициализация ---------------------------- */

static int audio_init_ports(AudioCall *c, int input_device_id, int output_device_id) {
    PaError pe;

    pe = Pa_Initialize();
    if (pe != paNoError) {
        fprintf(stderr, "PortAudio init error: %s\n", Pa_GetErrorText(pe));
        return -1;
    }

    // Получим информацию о доступных устройствах для отладки
    printf("Available audio hosts:\n");
    for (int i = 0; i < Pa_GetHostApiCount(); i++) {
        const PaHostApiInfo* info = Pa_GetHostApiInfo(i);
        printf("%d: %s\n", i, info->name);
    }

    printf("Default input device: %d\n", Pa_GetDefaultInputDevice());
    printf("Default output device: %d\n", Pa_GetDefaultOutputDevice());

    // Попробуем несколько подходов к открытию потоков

    // Способ 1: Прямое открытие с параметрами
    PaStreamParameters inParams, outParams;
    memset(&inParams, 0, sizeof(inParams));
    memset(&outParams, 0, sizeof(outParams));

    // Используем указанное устройство или дефолтное
    if (input_device_id >= 0) {
        inParams.device = input_device_id;
        printf("Using specified input device: %d\n", input_device_id);
    } else {
        inParams.device = Pa_GetDefaultInputDevice();
    }

    if (inParams.device != paNoDevice) {
        const PaDeviceInfo* indev = Pa_GetDeviceInfo(inParams.device);
        if (indev) {
            printf("Input device: %s\n", indev->name);
            inParams.channelCount = AC_CHANNELS;
            inParams.sampleFormat = paInt16;
            inParams.suggestedLatency = indev->defaultLowInputLatency;
            inParams.hostApiSpecificStreamInfo = NULL;
        } else {
            inParams.device = paNoDevice;
        }
    }

    // Используем указанное устройство или дефолтное
    if (output_device_id >= 0) {
        outParams.device = output_device_id;
        printf("Using specified output device: %d\n", output_device_id);
    } else {
        outParams.device = Pa_GetDefaultOutputDevice();
    }

    if (outParams.device != paNoDevice) {
        const PaDeviceInfo* outdev = Pa_GetDeviceInfo(outParams.device);
        if (outdev) {
            printf("Output device: %s\n", outdev->name);
            outParams.channelCount = AC_CHANNELS;
            outParams.sampleFormat = paInt16;
            outParams.suggestedLatency = outdev->defaultLowOutputLatency;
            outParams.hostApiSpecificStreamInfo = NULL;
        } else {
            outParams.device = paNoDevice;
        }
    }

    // Пробуем открыть входной поток
    if (inParams.device != paNoDevice) {
        pe = Pa_OpenStream(&c->in_stream, &inParams, NULL, AC_SAMPLE_RATE,
                           AC_FRAME_SAMPLES, paClipOff, NULL, NULL);
        if (pe != paNoError) {
            fprintf(stderr, "Pa_OpenStream(in) error: %s\n", Pa_GetErrorText(pe));
            c->in_stream = NULL;
        }
    }

    // Если не удалось, пробуем дефолтный поток
    if (c->in_stream == NULL) {
        pe = Pa_OpenDefaultStream(&c->in_stream, AC_CHANNELS, 0, paInt16, 
                                 AC_SAMPLE_RATE, AC_FRAME_SAMPLES, NULL, NULL);
        if (pe != paNoError) {
            fprintf(stderr, "Pa_OpenDefaultStream(in) error: %s\n", Pa_GetErrorText(pe));
            fprintf(stderr, "Warning: Audio input will be disabled\n");
            c->in_stream = NULL;
        }
    }

    // Пробуем открыть выходной поток
    if (outParams.device != paNoDevice) {
        pe = Pa_OpenStream(&c->out_stream, NULL, &outParams, AC_SAMPLE_RATE,
                           AC_FRAME_SAMPLES, paClipOff, NULL, NULL);
        if (pe != paNoError) {
            fprintf(stderr, "Pa_OpenStream(out) error: %s\n", Pa_GetErrorText(pe));
            c->out_stream = NULL;
        }
    }

    // Если не удалось, пробуем дефолтный поток
    if (c->out_stream == NULL) {
        pe = Pa_OpenDefaultStream(&c->out_stream, 0, AC_CHANNELS, paInt16,
                                 AC_SAMPLE_RATE, AC_FRAME_SAMPLES, NULL, NULL);
        if (pe != paNoError) {
            fprintf(stderr, "Pa_OpenDefaultStream(out) error: %s\n", Pa_GetErrorText(pe));
            fprintf(stderr, "Warning: Audio output will be disabled\n");
            c->out_stream = NULL;
        }
    }

    // Запускаем потоки, если они были созданы
    if (c->in_stream) {
        if ((pe = Pa_StartStream(c->in_stream)) != paNoError) {
            fprintf(stderr, "Pa_StartStream(in) error: %s\n", Pa_GetErrorText(pe));
            Pa_CloseStream(c->in_stream);
            c->in_stream = NULL;
        }
    }

    if (c->out_stream) {
        if ((pe = Pa_StartStream(c->out_stream)) != paNoError) {
            fprintf(stderr, "Pa_StartStream(out) error: %s\n", Pa_GetErrorText(pe));
            Pa_CloseStream(c->out_stream);
            c->out_stream = NULL;
        }
    }

    // Если оба потока не работают, это фатальная ошибка
    if (c->in_stream == NULL && c->out_stream == NULL) {
        fprintf(stderr, "Both audio streams failed to initialize\n");
        return -1;
    }

    printf("Audio initialized: input %s, output %s\n",
           c->in_stream ? "enabled" : "disabled",
           c->out_stream ? "enabled" : "disabled");
    
    return 0;
}

static int audio_init_codec(AudioCall *c) {
    int err = 0;
    c->enc = opus_encoder_create(AC_SAMPLE_RATE, AC_CHANNELS, AC_APP, &err);
    if (!c->enc || err != OPUS_OK) {
        fprintf(stderr, "opus_encoder_create error: %d\n", err);
        return -1;
    }
    mic_dsp_init(&c->mic, c->mic_gain_db, c->mic_ns, AC_SAMPLE_RATE);

    opus_encoder_ctl(c->enc, OPUS_SET_BITRATE(AC_OPUS_BITRATE));
    opus_encoder_ctl(c->enc, OPUS_SET_COMPLEXITY(AC_OPUS_COMPLEXITY));
    opus_encoder_ctl(c->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    opus_encoder_ctl(c->enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(c->enc, OPUS_SET_PACKET_LOSS_PERC(10));

    /* Decoders are created per participant when that participant is first
       heard, not here: one decoder cannot serve several senders. */
    for (int i = 0; i < AC_MAX_MIX; i++) {
        c->mix[i].slot = -1;
        c->mix[i].dec = NULL;
        c->mix[i].last_ms = 0;
        c->mix[i].prefilled = 0;
        c->mix[i].frames = 0;
        if (pcmring_init(&c->mix[i].ring, 32) != 0) {
            fprintf(stderr, "pcmring_init failed for mix slot %d\n", i);
            for (int j = 0; j < i; j++) pcmring_free(&c->mix[j].ring);
            ac_free_wiped(c);
            return -1;
        }
    }
#ifdef _WIN32
    InitializeCriticalSection(&c->mix_lock);
#else
    pthread_mutex_init(&c->mix_lock, NULL);
#endif
    c->mix_ready = 1;

    if (0) {
        fprintf(stderr, "opus_decoder_create error: %d\n", err);
        return -1;
    }
    return 0;
}

/* ------------------------ API: старт/стоп звонка ------------------------- */

void audio_call_stop(AudioCall *c) {
    if (!c) return;
    atomic_store(&c->running, 0);

#ifdef _WIN32
    if (c->th_send) {
        WaitForSingleObject(c->th_send, INFINITE);
        CloseHandle(c->th_send);
        c->th_send = NULL;
    }
    if (c->th_recv) {
        WaitForSingleObject(c->th_recv, INFINITE);
        CloseHandle(c->th_recv);
        c->th_recv = NULL;
    }
    if (c->th_play) {
        WaitForSingleObject(c->th_play, INFINITE);
        CloseHandle(c->th_play);
        c->th_play = NULL;
    }
#else
    if (c->th_send) {
        pthread_join(c->th_send, NULL);
        c->th_send = 0;
    }
    if (c->th_recv) {
        pthread_join(c->th_recv, NULL);
        c->th_recv = 0;
    }
    if (c->th_play) {
        pthread_join(c->th_play, NULL);
        c->th_play = 0;
    }
#endif

    if (c->in_stream) {
        Pa_StopStream(c->in_stream);
        Pa_CloseStream(c->in_stream);
        c->in_stream = NULL;
    }
    if (c->out_stream){
        Pa_StopStream(c->out_stream);
        Pa_CloseStream(c->out_stream);
        c->out_stream = NULL;
    }
    Pa_Terminate();

    if (c->enc) {
        opus_encoder_destroy(c->enc);
        c->enc = NULL;
    }


    if (c->tcp_sock) {
        CLOSESOCK(c->tcp_sock);
        c->tcp_sock = 0;
    }
    if (c->sock) {
        CLOSESOCK(c->sock);
        c->sock = 0;
    }

#ifdef _WIN32
    if (c->relay_mode) DeleteCriticalSection(&c->tcp_send_lock);
#else
    if (c->relay_mode) pthread_mutex_destroy(&c->tcp_send_lock);
#endif

    /* One line per participant we installed, with how many of their packets
     * actually decrypted. A peer that was installed but never decrypted is
     * the exact symptom of a key that both ends derived differently, which
     * is invisible from either side alone. */
    for (int i = 0; i < MS_MAX_SLOTS; i++) {
        if (!c->senders.slots[i].used) continue;
        const uint8_t *sid = c->senders.slots[i].sid;
        uint64_t mixed = 0;
        for (int k = 0; k < AC_MAX_MIX; k++) {
            if (c->mix[k].slot == i) { mixed = c->mix[k].frames; break; }
        }
        printf("[MEDIA] peer %02x%02x%02x decrypted %llu mixed %llu\n",
               sid[0], sid[1], sid[2],
               (unsigned long long)c->rx_count[i],
               (unsigned long long)mixed);
    }
    fflush(stdout);

    mix_teardown(c);

    /* Wipe every secret before the memory goes back to the allocator: the
       call key, the derived send key, the HELLO key, our salt, the identity
       secret key and every per-sender key in the table. The pre-group code
       wiped none of them. */

    ms_clear(&c->senders);
    sodium_memzero(c, sizeof *c);
    free(c);
}

/** Drop a half-built call object, wiping its key material first. */
static void ac_free_wiped(AudioCall *c) {
    if (!c) return;
    sodium_memzero(c, sizeof *c);
    free(c);
}

/*
 * Настройки микрофона - свойство запуска, а не отдельного звонка: человек
 * выставляет их под свой микрофон один раз. Держим их здесь, а не тянем
 * двумя лишними параметрами через всю цепочку вызовов, каждый из которых
 * пришлось бы править в четырёх местах.
 */
static float          g_mic_gain_db = 0.0f;
static mic_ns_level_t g_mic_ns      = MIC_NS_MEDIUM;

static void audio_call_set_mic(float gain_db, mic_ns_level_t ns) {
    g_mic_gain_db = gain_db;
    g_mic_ns      = ns;
}

int audio_call_start(AudioCall **out_call,
                     const char *remote_ip, uint16_t remote_port,
                     uint16_t bind_port,
                     int is_caller,
                     const uint8_t key[AES_GCM_KEY_LEN],
                     const uint8_t call_id[MK_CALLID_BYTES],
                     int input_device_id,
                     int output_device_id,
                     const uint8_t *id_pk,
                     const uint8_t *id_sk,
                     int relay_mode,
                     const char *relay_room,
                     const char *relay_name)
{
    if (!out_call || !key || !call_id) return -1;
    if (net_init_once() != 0) return -1;
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return -1;
    }
    /* Refuse rather than fall back to zeros. An all-zero call_id is what a
       path that forgot to plumb the field through would produce, and taking
       it would silently drop the cross-call replay barrier while still
       appearing to work. */
    if (sodium_is_zero(call_id, MK_CALLID_BYTES)) {
        fprintf(stderr, "Error: a call id is required to start a call\n");
        return -1;
    }

    AudioCall *c = (AudioCall*)calloc(1, sizeof(AudioCall));
    if (!c) return -1;
    memcpy(c->master_key, key, MK_KEY_BYTES);
    memcpy(c->call_id, call_id, MK_CALLID_BYTES);
    atomic_store(&c->have_peer, 0);
    atomic_store(&c->seq_tx, 0);
    atomic_store(&c->running, 1);

    /* Initialize identity. This has to happen before the keys are derived:
       when we have an identity, our public key is bound into them. */
    if (id_pk && id_sk) {
        c->has_identity = 1;
        memcpy(c->identity_pk, id_pk, IDENTITY_PK_BYTES);
        memcpy(c->identity_sk, id_sk, IDENTITY_SK_BYTES);
        memcpy(c->idbind, id_pk, MK_IDBIND_BYTES);
    } else {
        c->has_identity = 0;
        memset(c->idbind, 0, MK_IDBIND_BYTES);   /* unsigned call: 32 zero bytes */
    }
    c->peer_verified = 0;
    identity_default_known_keys_path(c->known_keys_path, sizeof(c->known_keys_path));

    /* Our salt is drawn exactly once, here, before any thread exists, and is
       never re-drawn mid-call: our tag and every key we send under hang off
       it, so replacing it would restart our counter under a fresh key. */
    randombytes_buf(c->own_salt, MK_SALT_BYTES);
    if (mk_sender_id(c->master_key, c->call_id, c->own_salt, c->idbind,
                     c->own_sid) != 0 ||
        mk_derive_sender(c->master_key, MK_STREAM_AUDIO, AC_KEY_VERSION,
                         c->call_id, c->own_salt, c->idbind,
                         c->send_key_audio) != 0 ||
        mk_hello_key(c->master_key, c->call_id, c->hello_key) != 0 ||
        ms_init(&c->senders, c->master_key, c->call_id, c->own_salt) != MS_OK) {
        fprintf(stderr, "media key derivation failed\n");
        ac_free_wiped(c);
        return -1;
    }
    printf("[MEDIA] self %02x%02x%02x\n",
           c->own_sid[0], c->own_sid[1], c->own_sid[2]);
    printf("Media keys ready; our sender tag is %02x%02x%02x\n",
           c->own_sid[0], c->own_sid[1], c->own_sid[2]);

    /* Relay mode setup */
    c->mic_gain_db = g_mic_gain_db;
    c->mic_ns      = g_mic_ns;

    c->relay_mode = relay_mode;
    /*
     * Комната ретранслятору называется меткой, а не именем.
     *
     * Звонок идёт отдельным процессом и подключается к тому же серверу
     * своим соединением. Передай он название как есть - на ретрансляторе
     * снова появилась бы строка «general», ровно та, которую чат уже
     * перестал показывать: достаточно одного звонка, чтобы свести на нет
     * всю скрытность комнаты.
     *
     * Метка выводится тем же хешем, что и в чате, поэтому сходится и с
     * собеседником, и с записью нашего чат-клиента на сервере - по ней
     * сервер привязывает UDP-адрес звонка к нужному соединению.
     */
    if (relay_mode && relay_room && relay_name) {
        char wire[IDENTITY_WIRE_ROOM_LEN];
        const char *routed = relay_room;
        if (identity_wire_room(relay_room, wire) == 0) routed = wire;
        strncpy(c->relay_room, routed, sizeof(c->relay_room) - 1);
        c->relay_room[sizeof(c->relay_room) - 1] = '\0';
        strncpy(c->relay_name, relay_name, sizeof(c->relay_name) - 1);
        c->relay_name[sizeof(c->relay_name) - 1] = '\0';
    } else {
        c->relay_mode = 0;
        c->relay_room[0] = '\0';
        c->relay_name[0] = '\0';
    }

    if (0) {
        ac_free_wiped(c);
        return -1;
    }

    c->sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (c->sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "socket() failed\n");
        mix_teardown(c);
        ac_free_wiped(c);
        return -1;
    }

    /* Bound how long recvfrom may block, so the receive thread notices
     * c->running going to zero.
     *
     * Without this the thread sits in recvfrom forever, audio_call_stop
     * blocks in pthread_join, and Ctrl+C never completes: the process has
     * to be killed. That also means none of the teardown ever ran - not the
     * key wiping, not the socket close. The defect predates the group-call
     * work, but the wiping added with it is worthless while it stands. */
    {
#ifdef _WIN32
        DWORD rcv_to = 200;
        setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&rcv_to, sizeof rcv_to);
#else
        struct timeval rcv_to;
        rcv_to.tv_sec = 0;
        rcv_to.tv_usec = 200000;
        setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof rcv_to);
#endif
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(bind_port);
    if (bind(c->sock, (struct sockaddr*)&local, sizeof(local)) == SOCK_ERR) {
        fprintf(stderr, "bind() failed (port %u)\n", bind_port);
        CLOSESOCK(c->sock);
        mix_teardown(c);
        ac_free_wiped(c);
        return -1;
    }

    c->peer_set = 0;
    if (remote_ip && remote_port != 0) {
        memset(&c->peer, 0, sizeof(c->peer));
        c->peer.sin_family = AF_INET;
        c->peer.sin_port = htons(remote_port);
        if (resolve_host_v4(remote_ip, &c->peer.sin_addr) != 0) {
            fprintf(stderr, "cannot resolve host %s\n", remote_ip);
            CLOSESOCK(c->sock);
            mix_teardown(c);
            ac_free_wiped(c);
            return -1;
        }
        c->peer_set = 1;
    }

    if (audio_init_ports(c, input_device_id, output_device_id) != 0) {
        CLOSESOCK(c->sock);
        mix_teardown(c);
        ac_free_wiped(c);
        return -1;
    }
    if (audio_init_codec(c) != 0) {
        Pa_Terminate();
        CLOSESOCK(c->sock);
        mix_teardown(c);
        ac_free_wiped(c);
        return -1;
    }

    /* TCP relay: connect to server and register */
    if (c->relay_mode && remote_ip && remote_port != 0) {
#ifdef _WIN32
        InitializeCriticalSection(&c->tcp_send_lock);
#else
        pthread_mutex_init(&c->tcp_send_lock, NULL);
#endif
        if (tcp_relay_connect(c, remote_ip, remote_port) != 0) {
            Pa_Terminate(); CLOSESOCK(c->sock);
            mix_teardown(c); ac_free_wiped(c);
            return -1;
        }
        if (tcp_relay_register(c) != 0) {
            fprintf(stderr, "TCP relay registration failed\n");
            CLOSESOCK(c->tcp_sock); Pa_Terminate(); CLOSESOCK(c->sock);
            mix_teardown(c); ac_free_wiped(c);
            return -1;
        }
        c->peer_set = 1; /* so send guards pass */
    } else if (c->relay_mode && c->peer_set) {
        /* Fallback: UDP relay registration */
        send_udp_registration(c);
        printf("UDP relay registration sent (room=%s, name=%s)\n",
               c->relay_room, c->relay_name);
    }

    if (is_caller && (c->peer_set || c->tcp_sock)) {
        send_hello(c);
    }

    ThreadArgs *a1 = (ThreadArgs*)malloc(sizeof(ThreadArgs));
    ThreadArgs *a2 = (ThreadArgs*)malloc(sizeof(ThreadArgs));
    if (!a1 || !a2) {
        if (a1) free(a1);
        if (a2) free(a2);
        /* cleanup */
        if (c->enc) opus_encoder_destroy(c->enc);
        Pa_Terminate();
        CLOSESOCK(c->sock);
        mix_teardown(c);
        ac_free_wiped(c);
        return -1;
    }
    a1->c = c; a2->c = c;

#ifdef _WIN32
    ThreadArgs *a3 = (ThreadArgs*)malloc(sizeof(ThreadArgs));
    if (!a3) { audio_call_stop(c); return -1; }
    a3->c = c;
    c->th_recv = CreateThread(NULL, 0, th_recv_func, a1, 0, NULL);
    c->th_send = CreateThread(NULL, 0, th_send_func, a2, 0, NULL);
    c->th_play = CreateThread(NULL, 0, th_play_func, a3, 0, NULL);
    if (!c->th_recv || !c->th_send) {
        audio_call_stop(c);
        return -1;
    }
#else
    ThreadArgs *a3 = (ThreadArgs*)malloc(sizeof(ThreadArgs));
    if (!a3) { audio_call_stop(c); return -1; }
    a3->c = c;
    if (pthread_create(&c->th_recv, NULL, th_recv_func, a1) != 0 ||
        pthread_create(&c->th_send, NULL, th_send_func, a2) != 0 ||
        pthread_create(&c->th_play, NULL, th_play_func, a3) != 0) {
        audio_call_stop(c);
        return -1;
    }
#endif

    *out_call = c;
    return 0;
}

/* -------------------------- Утилиты для main ----------------------------- */

/* hex2bytes теперь в audio_crypto.h */

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", b[i]);
    printf("\n");
}

/**
 * @brief Read key from file securely
 *
 * @param filename Path to key file
 * @param buffer Buffer to store key (hex string)
 * @param bufsize Size of buffer
 * @return 0 on success, -1 on error
 */
static int read_key_from_file(const char *filename, char *buffer, size_t bufsize) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open key file '%s'\n", filename);
        return -1;
    }

    // Read first line from file
    if (!fgets(buffer, (int)bufsize, f)) {
        fprintf(stderr, "Error: Cannot read from key file '%s'\n", filename);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Remove newline and whitespace
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || buffer[len-1] == ' ')) {
        buffer[len-1] = '\0';
        len--;
    }

    if (len == 0) {
        fprintf(stderr, "Error: Key file is empty\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Read key from stdin securely
 *
 * @param buffer Buffer to store key (hex string)
 * @param bufsize Size of buffer
 * @param interactive Show prompt if true
 * @return 0 on success, -1 on error
 */
static int read_key_from_stdin(char *buffer, size_t bufsize, int interactive) {
    if (interactive) {
        fprintf(stderr, "Enter audio call key (64 hex chars): ");
        fflush(stderr);
    }

    if (!fgets(buffer, (int)bufsize, stdin)) {
        fprintf(stderr, "Error: Failed to read key from stdin\n");
        return -1;
    }

    // Remove newline and whitespace
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || buffer[len-1] == ' ')) {
        buffer[len-1] = '\0';
        len--;
    }

    if (len == 0) {
        fprintf(stderr, "Error: Empty key provided\n");
        return -1;
    }

    return 0;
}

/* ------------------------------- HUB (ретранслятор) --------------------- */

/* Весь код Hub теперь в audio_hub.h и audio_hub.c:
   - HubClient, Hub structures
   - hub_init(), hub_find_or_add(), hub_prune(), hub_forward()
   - hub_main(uint16_t bind_port) - главная функция хаба
*/

/* ------------------------------- main ------------------------------------ */

static volatile atomic_int g_sigint = 0;

#ifdef _WIN32
static BOOL WINAPI ctrlc_handler(DWORD ev) {
    if (ev == CTRL_C_EVENT) {
        atomic_store(&g_sigint, 1);
        return TRUE;
    }
    return FALSE;
}
#else
static void ctrlc_handler(int sig) {
    (void)sig;
    atomic_store(&g_sigint, 1);
}
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

int main(int argc, char **argv) {
    /*
     * Настройки микрофона разбираются раньше выбора режима: они одинаково
     * нужны и прямому звонку, и звонку через ретранслятор, а режимов у
     * запуска четыре. Разбор в одном месте избавляет от четырёх копий,
     * которые разошлись бы при первой же правке.
     */
    {
        float          mic_gain_db = 0.0f;
        mic_ns_level_t mic_ns      = MIC_NS_MEDIUM;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--mic-gain") == 0 && i + 1 < argc) {
                mic_gain_db = (float)atof(argv[i + 1]);
            } else if (strcmp(argv[i], "--noise-suppress") == 0 && i + 1 < argc) {
                if (mic_ns_from_string(argv[i + 1], &mic_ns) != 0) {
                    fprintf(stderr, "unknown noise suppression level: %s "
                                    "(off, low, medium, high)\n", argv[i + 1]);
                    return 1;
                }
            }
        }
        audio_call_set_mic(mic_gain_db, mic_ns);
    }

    if (argc < 2) {
        fprintf(stderr,
                "Usage:\n"
                "  %s genkey\n"
                "  %s listdevices\n"
                "  %s call <remote_ip> <remote_port> --call-id HEX [--key-file FILE] [local_bind_port] [input_dev] [output_dev]\n"
                "  %s listen <local_bind_port> --call-id HEX [--key-file FILE] [input_dev] [output_dev]\n"
                "  %s hub <bind_port>\n"
                "\n"
                "  --call-id HEX         REQUIRED. 32 hex chars identifying this call, from\n"
                "                        the invite. Every participant must pass the same\n"
                "                        value or their media keys will not match.\n"
                "\n"
                "Key input methods (in order of priority):\n"
                "  1. --key-file FILE    Read key from file (recommended for scripts)\n"
                "  2. stdin              Read key from standard input (interactive or piped)\n"
                "  3. <hexkey32>         Direct key argument (DEPRECATED - insecure, visible in process list)\n",
                argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        if (sodium_init() < 0) return 1;
        uint8_t key[AES_GCM_KEY_LEN];
        randombytes_buf(key, sizeof(key));

        // SECURITY: Output key to stdout for clipboard copy
        // The GUI or user can copy it to clipboard directly
        // DO NOT save to file automatically (user can redirect output if needed)
        for (size_t i = 0; i < sizeof(key); ++i) {
            printf("%02x", key[i]);
        }
        printf("\n");

        sodium_memzero(key, sizeof key);
        fprintf(stderr, "Audio call key generated successfully.\n");
        fprintf(stderr, "IMPORTANT: Copy the key above to clipboard and share it securely.\n");
        fprintf(stderr, "           The key is NOT saved to disk for security reasons.\n");
        return 0;
    }

    if (strcmp(argv[1], "listdevices") == 0) {
        PaError pe = Pa_Initialize();
        if (pe != paNoError) {
            fprintf(stderr, "PortAudio init error: %s\n", Pa_GetErrorText(pe));
            return 1;
        }

        int numDevices = Pa_GetDeviceCount();
        if (numDevices < 0) {
            fprintf(stderr, "Pa_GetDeviceCount error: %s\n", Pa_GetErrorText(numDevices));
            Pa_Terminate();
            return 1;
        }

        printf("Total devices: %d\n", numDevices);
        printf("Default input: %d\n", Pa_GetDefaultInputDevice());
        printf("Default output: %d\n", Pa_GetDefaultOutputDevice());
        printf("\n");

        for (int i = 0; i < numDevices; i++) {
            const PaDeviceInfo *info = Pa_GetDeviceInfo(i);
            if (!info) continue;

            const PaHostApiInfo *hostInfo = Pa_GetHostApiInfo(info->hostApi);
            const char *hostName = hostInfo ? hostInfo->name : "Unknown";

            // Include Host API in device name to avoid duplicates
            printf("Device %d: %s (%s)\n", i, info->name, hostName);
            printf("  Host API: %s\n", hostName);
            printf("  Max input channels: %d\n", info->maxInputChannels);
            printf("  Max output channels: %d\n", info->maxOutputChannels);
            printf("  Default sample rate: %.0f Hz\n", info->defaultSampleRate);
            printf("\n");
        }

        Pa_Terminate();
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
            fprintf(stderr, "Usage: %s call <remote_ip> <remote_port> --call-id HEX [--key-file FILE] [--identity-file FILE] [--no-sign] [local_bind_port] [input_dev] [output_dev]\n", argv[0]);
            return 1;
        }
        const char *ip = argv[2];
        uint16_t rport = (uint16_t)atoi(argv[3]);

        // Parse optional arguments
        const char *keyfile = NULL;
        const char *hexkey_arg = NULL;
        const char *identity_file = NULL;
        int no_sign = 0;
        uint16_t lport = 0;
        int input_dev = -1;
        int output_dev = -1;
        int using_deprecated_key_arg = 0;

        int arg_idx = 4;
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "--key-file") == 0 && arg_idx + 1 < argc) {
                keyfile = argv[arg_idx + 1];
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--identity-file") == 0 && arg_idx + 1 < argc) {
                identity_file = argv[arg_idx + 1];
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--call-id") == 0 && arg_idx + 1 < argc) {
                if (mk_call_id_parse(argv[arg_idx + 1], g_call_id) != 0) {
                    fprintf(stderr, "Error: --call-id must be %d hex characters and not all zero\n",
                            MK_CALLID_BYTES * 2);
                    return 1;
                }
                g_have_call_id = 1;
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--no-sign") == 0) {
                no_sign = 1;
                arg_idx++;
            } else {
                // Legacy positional arguments: [hexkey] [local_bind_port] [input_dev] [output_dev]
                if (hexkey_arg == NULL && strlen(argv[arg_idx]) == 64) {
                    hexkey_arg = argv[arg_idx];
                    using_deprecated_key_arg = 1;
                    arg_idx++;
                } else if (lport == 0) {
                    lport = (uint16_t)atoi(argv[arg_idx]);
                    arg_idx++;
                } else if (input_dev == -1) {
                    input_dev = atoi(argv[arg_idx]);
                    arg_idx++;
                } else if (output_dev == -1) {
                    output_dev = atoi(argv[arg_idx]);
                    arg_idx++;
                } else {
                    arg_idx++;
                }
            }
        }

        /* The call id is mandatory: it is mixed into every media key, so
           without it two calls under one room key would produce the same key
           stream and a recording of one could be replayed into the other. */
        if (!g_have_call_id) {
            fprintf(stderr, "Error: --call-id is required (32 hex chars from the call invite).\n");
            fprintf(stderr, "       Every participant must pass the same value.\n");
            return 1;
        }

        // Buffer for key storage
        static char key_buffer[256];
        memset(key_buffer, 0, sizeof(key_buffer));
        const char *hexkey = NULL;

        // Priority 1: Read from --key-file
        if (keyfile) {
            if (read_key_from_file(keyfile, key_buffer, sizeof(key_buffer)) != 0) {
                return 1;
            }
            hexkey = key_buffer;
        }
        // Priority 2: Read from stdin (interactive or piped)
        else if (!hexkey_arg) {
            int is_interactive = isatty(fileno(stdin));
            if (read_key_from_stdin(key_buffer, sizeof(key_buffer), is_interactive) != 0) {
                return 1;
            }
            hexkey = key_buffer;
        }
        // Priority 3: Deprecated hexkey argument
        else if (using_deprecated_key_arg) {
            fprintf(stderr, "\n");
            fprintf(stderr, "WARNING: Using key as command line argument is insecure!\n");
            fprintf(stderr, "         The key is visible in process lists (ps, top, Task Manager).\n");
            fprintf(stderr, "         Use --key-file or stdin instead.\n");
            fprintf(stderr, "\n");
            hexkey = hexkey_arg;
        }

        uint8_t key[AES_GCM_KEY_LEN];
        if (hex2bytes(hexkey, key, sizeof(key)) != 0) {
            fprintf(stderr, "Invalid key (must be 64 hex chars)\n");
            return 1;
        }

        /* Load identity (optional) */
        uint8_t id_pk[IDENTITY_PK_BYTES], id_sk[IDENTITY_SK_BYTES];
        int has_identity = 0;
        if (!no_sign) {
            char id_path[512];
            if (identity_file) {
                strncpy(id_path, identity_file, sizeof(id_path) - 1);
                id_path[sizeof(id_path) - 1] = '\0';
            } else {
                identity_default_path(id_path, sizeof(id_path));
            }
            if (identity_load(id_path, id_pk, id_sk) == 0) {
                has_identity = 1;
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(id_pk, fp);
                fprintf(stderr, "Identity loaded: %s\n", fp);
            }
        }

        AudioCall *call = NULL;
        if (audio_call_start(&call, ip, rport, lport, 1, key, g_call_id, input_dev, output_dev,
                             has_identity ? id_pk : NULL,
                             has_identity ? id_sk : NULL,
                             0, NULL, NULL) != 0) {
            fprintf(stderr, "Failed to start call\n");
            if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
            sodium_memzero(key, sizeof key);
            sodium_memzero(key_buffer, sizeof key_buffer);
            return 1;
        }
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
        /* The room key lives inside the call object now; nothing out here
           needs it any more. */
        sodium_memzero(key, sizeof key);
        sodium_memzero(key_buffer, sizeof key_buffer);

        setup_signal();
        printf("Calling %s:%u (press Ctrl+C to stop)\n", ip, rport);
        while (!atomic_load(&g_sigint)) {
            msleep(100);
        }
        audio_call_stop(call);
        printf("Call ended\n");
        return 0;
    }

    if (strcmp(argv[1], "listen") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s listen <local_bind_port> --call-id HEX [--key-file FILE] [--identity-file FILE] [--no-sign] [--mic-gain dB] [--noise-suppress off|low|medium|high] [input_dev] [output_dev]\n", argv[0]);
            return 1;
        }
        uint16_t lport = (uint16_t)atoi(argv[2]);

        // Parse optional arguments
        const char *keyfile = NULL;
        const char *hexkey_arg = NULL;
        const char *identity_file = NULL;
        int no_sign = 0;
        int input_dev = -1;
        int output_dev = -1;
        int using_deprecated_key_arg = 0;

        int arg_idx = 3;
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "--key-file") == 0 && arg_idx + 1 < argc) {
                keyfile = argv[arg_idx + 1];
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--identity-file") == 0 && arg_idx + 1 < argc) {
                identity_file = argv[arg_idx + 1];
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--call-id") == 0 && arg_idx + 1 < argc) {
                if (mk_call_id_parse(argv[arg_idx + 1], g_call_id) != 0) {
                    fprintf(stderr, "Error: --call-id must be %d hex characters and not all zero\n",
                            MK_CALLID_BYTES * 2);
                    return 1;
                }
                g_have_call_id = 1;
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--no-sign") == 0) {
                no_sign = 1;
                arg_idx++;
            } else {
                // Legacy positional arguments: [hexkey] [input_dev] [output_dev]
                if (hexkey_arg == NULL && strlen(argv[arg_idx]) == 64) {
                    hexkey_arg = argv[arg_idx];
                    using_deprecated_key_arg = 1;
                    arg_idx++;
                } else if (input_dev == -1) {
                    input_dev = atoi(argv[arg_idx]);
                    arg_idx++;
                } else if (output_dev == -1) {
                    output_dev = atoi(argv[arg_idx]);
                    arg_idx++;
                } else {
                    arg_idx++;
                }
            }
        }

        /* The call id is mandatory: it is mixed into every media key, so
           without it two calls under one room key would produce the same key
           stream and a recording of one could be replayed into the other. */
        if (!g_have_call_id) {
            fprintf(stderr, "Error: --call-id is required (32 hex chars from the call invite).\n");
            fprintf(stderr, "       Every participant must pass the same value.\n");
            return 1;
        }

        // Buffer for key storage
        static char key_buffer[256];
        memset(key_buffer, 0, sizeof(key_buffer));
        const char *hexkey = NULL;

        // Priority 1: Read from --key-file
        if (keyfile) {
            if (read_key_from_file(keyfile, key_buffer, sizeof(key_buffer)) != 0) {
                return 1;
            }
            hexkey = key_buffer;
        }
        // Priority 2: Read from stdin (interactive or piped)
        else if (!hexkey_arg) {
            int is_interactive = isatty(fileno(stdin));
            if (read_key_from_stdin(key_buffer, sizeof(key_buffer), is_interactive) != 0) {
                return 1;
            }
            hexkey = key_buffer;
        }
        // Priority 3: Deprecated hexkey argument
        else if (using_deprecated_key_arg) {
            fprintf(stderr, "\n");
            fprintf(stderr, "WARNING: Using key as command line argument is insecure!\n");
            fprintf(stderr, "         The key is visible in process lists (ps, top, Task Manager).\n");
            fprintf(stderr, "         Use --key-file or stdin instead.\n");
            fprintf(stderr, "\n");
            hexkey = hexkey_arg;
        }

        uint8_t key[AES_GCM_KEY_LEN];
        if (hex2bytes(hexkey, key, sizeof(key)) != 0) {
            fprintf(stderr, "Invalid key (must be 64 hex chars)\n");
            return 1;
        }

        /* Load identity (optional) */
        uint8_t id_pk[IDENTITY_PK_BYTES], id_sk[IDENTITY_SK_BYTES];
        int has_identity = 0;
        if (!no_sign) {
            char id_path[512];
            if (identity_file) {
                strncpy(id_path, identity_file, sizeof(id_path) - 1);
                id_path[sizeof(id_path) - 1] = '\0';
            } else {
                identity_default_path(id_path, sizeof(id_path));
            }
            if (identity_load(id_path, id_pk, id_sk) == 0) {
                has_identity = 1;
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(id_pk, fp);
                fprintf(stderr, "Identity loaded: %s\n", fp);
            }
        }

        AudioCall *call = NULL;
        if (audio_call_start(&call, NULL, 0, lport, 0, key, g_call_id, input_dev, output_dev,
                             has_identity ? id_pk : NULL,
                             has_identity ? id_sk : NULL,
                             0, NULL, NULL) != 0) {
            fprintf(stderr, "Failed to start listener\n");
            if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
            sodium_memzero(key, sizeof key);
            sodium_memzero(key_buffer, sizeof key_buffer);
            return 1;
        }
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
        /* The room key lives inside the call object now; nothing out here
           needs it any more. */
        sodium_memzero(key, sizeof key);
        sodium_memzero(key_buffer, sizeof key_buffer);

        setup_signal();
        printf("Listening on *:%u (press Ctrl+C to stop)\n", lport);
        while (!atomic_load(&g_sigint)) {
            msleep(100);
        }
        audio_call_stop(call);
        printf("Listener stopped\n");
        return 0;
    }

    if (strcmp(argv[1], "relay") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s relay <server_ip> <server_port> --room ROOM --name NAME --call-id HEX [--key-file FILE] [--identity-file FILE] [--no-sign] [--mic-gain dB] [--noise-suppress off|low|medium|high] [input_dev] [output_dev]\n", argv[0]);
            return 1;
        }
        const char *ip = argv[2];
        uint16_t rport = (uint16_t)atoi(argv[3]);

        const char *keyfile = NULL;
        const char *identity_file = NULL;
        const char *relay_room = NULL;
        const char *relay_name = NULL;
        int no_sign = 0;
        int input_dev = -1;
        int output_dev = -1;

        int arg_idx = 4;
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "--key-file") == 0 && arg_idx + 1 < argc) {
                keyfile = argv[arg_idx + 1]; arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--identity-file") == 0 && arg_idx + 1 < argc) {
                identity_file = argv[arg_idx + 1]; arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--call-id") == 0 && arg_idx + 1 < argc) {
                if (mk_call_id_parse(argv[arg_idx + 1], g_call_id) != 0) {
                    fprintf(stderr, "Error: --call-id must be %d hex characters and not all zero\n",
                            MK_CALLID_BYTES * 2);
                    return 1;
                }
                g_have_call_id = 1;
                arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--no-sign") == 0) {
                no_sign = 1; arg_idx++;
            } else if (strcmp(argv[arg_idx], "--room") == 0 && arg_idx + 1 < argc) {
                relay_room = argv[arg_idx + 1]; arg_idx += 2;
            } else if (strcmp(argv[arg_idx], "--name") == 0 && arg_idx + 1 < argc) {
                relay_name = argv[arg_idx + 1]; arg_idx += 2;
            } else {
                if (input_dev == -1) { input_dev = atoi(argv[arg_idx]); arg_idx++; }
                else if (output_dev == -1) { output_dev = atoi(argv[arg_idx]); arg_idx++; }
                else { arg_idx++; }
            }
        }

        if (!relay_room || !relay_name) {
            fprintf(stderr, "Error: --room and --name are required for relay mode\n");
            return 1;
        }

        /* The call id is mandatory: it is mixed into every media key, so
           without it two calls under one room key would produce the same key
           stream and a recording of one could be replayed into the other. */
        if (!g_have_call_id) {
            fprintf(stderr, "Error: --call-id is required (32 hex chars from the call invite).\n");
            fprintf(stderr, "       Every participant must pass the same value.\n");
            return 1;
        }

        static char key_buffer[256];
        memset(key_buffer, 0, sizeof(key_buffer));
        const char *hexkey = NULL;
        if (keyfile) {
            if (read_key_from_file(keyfile, key_buffer, sizeof(key_buffer)) != 0) return 1;
            hexkey = key_buffer;
        } else {
            int is_interactive = isatty(fileno(stdin));
            if (read_key_from_stdin(key_buffer, sizeof(key_buffer), is_interactive) != 0) return 1;
            hexkey = key_buffer;
        }

        uint8_t key[AES_GCM_KEY_LEN];
        if (hex2bytes(hexkey, key, sizeof(key)) != 0) {
            fprintf(stderr, "Invalid key (must be 64 hex chars)\n");
            return 1;
        }

        uint8_t id_pk[IDENTITY_PK_BYTES], id_sk[IDENTITY_SK_BYTES];
        int has_identity = 0;
        if (!no_sign) {
            char id_path[512];
            if (identity_file) {
                strncpy(id_path, identity_file, sizeof(id_path) - 1);
                id_path[sizeof(id_path) - 1] = '\0';
            } else {
                identity_default_path(id_path, sizeof(id_path));
            }
            if (identity_load(id_path, id_pk, id_sk) == 0) {
                has_identity = 1;
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(id_pk, fp);
                fprintf(stderr, "Identity loaded: %s\n", fp);
            }
        }

        AudioCall *call = NULL;
        if (audio_call_start(&call, ip, rport, 0, 1, key, g_call_id, input_dev, output_dev,
                             has_identity ? id_pk : NULL,
                             has_identity ? id_sk : NULL,
                             1, relay_room, relay_name) != 0) {
            fprintf(stderr, "Failed to start relay call\n");
            if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
            sodium_memzero(key, sizeof key);
            sodium_memzero(key_buffer, sizeof key_buffer);
            return 1;
        }
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
        /* The room key lives inside the call object now; nothing out here
           needs it any more. */
        sodium_memzero(key, sizeof key);
        sodium_memzero(key_buffer, sizeof key_buffer);

        setup_signal();
        printf("Relay call via %s:%u (room=%s, name=%s, press Ctrl+C to stop)\n",
               ip, rport, relay_room, relay_name);
        while (!atomic_load(&g_sigint)) {
            msleep(100);
        }
        audio_call_stop(call);
        printf("Relay call ended\n");
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}