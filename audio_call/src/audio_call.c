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
#include "identity.h"

/* -------------------------- Конфигурация --------------------------------- */

#define AC_SAMPLE_RATE       48000
#define AC_CHANNELS          1
#define AC_FRAME_MS          20
#define AC_FRAME_SAMPLES     ((AC_SAMPLE_RATE/1000)*AC_FRAME_MS) /* 960 */
#define AC_APP               OPUS_APPLICATION_VOIP
#define AC_OPUS_BITRATE      128000  /* 128 kbps for high quality */
#define AC_OPUS_COMPLEXITY   5
#define AC_UDP_RECV_BUFSZ    1500
#define AC_MAX_OPUS_BYTES    1275
#define AC_PCM_BYTES_PER_FR  (AC_FRAME_SAMPLES * sizeof(int16_t) * AC_CHANNELS)

/* Пакеты протокола */
#define PKT_VER_AUDIO  0x01
#define PKT_VER_STATS  0x04
#define PKT_VER_HELLO  0x7F

/* Stats exchange interval (ms) */
#define AC_STATS_INTERVAL_MS 2000

/* AES-GCM конфигурация */
#define AES_GCM_NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES  /* 12 байт */
#define AES_GCM_KEY_LEN   crypto_aead_aes256gcm_KEYBYTES   /* 32 байта */
#define AES_GCM_ABYTES    crypto_aead_aes256gcm_ABYTES     /* 16 байт */

/* Nonce для AES-GCM (12 байт): 4 байта префикс + 8 байт seq */
#define NONCE_PREFIX_LEN 4

/* Небольшая задержка */
#define PLAYOUT_BUFFER_FRAMES 6

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

/* HELLO flags for identity */
#define HELLO_FLAG_IDENTITY 0x01

/* Signed HELLO: [0x7F][prefix(4)][flags(1)][pk(32)][sig(64)] = 102 bytes */
#define HELLO_SIZE_SIGNED (1 + NONCE_PREFIX_LEN + 1 + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES)

typedef struct AudioCall {
    socket_t sock;
    struct sockaddr_in peer;
    int peer_set;

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

    uint8_t key[AES_GCM_KEY_LEN];
    uint8_t local_nonce_prefix[NONCE_PREFIX_LEN];
    uint8_t remote_nonce_prefix[NONCE_PREFIX_LEN];
    atomic_int remote_prefix_ready;

    atomic_uint_fast64_t seq_tx;

    PaStream *in_stream;
    PaStream *out_stream;
    OpusEncoder *enc;
    OpusDecoder *dec;

    PcmRing out_ring;

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
#else
    pthread_t th_send;
    pthread_t th_recv;
#endif
    atomic_int running;
} AudioCall;

/* --------------------------- Сеть: инициализация ------------------------- */

/* net_init_once() теперь в audio_network.h */

/* ------------------------- HELLO handshake -------------------------------- */

/* Forward declaration (defined after TCP relay helpers) */
static int ac_send_packet(AudioCall *c, const uint8_t *data, int len);

static int send_hello(AudioCall *c) {
    if (c->has_identity) {
        /* Signed HELLO: [0x7F][prefix(4)][flags(1)][pk(32)][sig(64)] */
        uint8_t pkt[HELLO_SIZE_SIGNED];
        pkt[0] = PKT_VER_HELLO;
        memcpy(pkt + 1, c->local_nonce_prefix, NONCE_PREFIX_LEN);
        pkt[1 + NONCE_PREFIX_LEN] = HELLO_FLAG_IDENTITY;
        memcpy(pkt + 1 + NONCE_PREFIX_LEN + 1, c->identity_pk, IDENTITY_PK_BYTES);
        identity_sign(c->local_nonce_prefix, NONCE_PREFIX_LEN,
                      c->identity_sk,
                      pkt + 1 + NONCE_PREFIX_LEN + 1 + IDENTITY_PK_BYTES);
        return ac_send_packet(c, pkt, (int)sizeof(pkt));
    } else {
        /* Unsigned HELLO: [0x7F][prefix(4)] */
        uint8_t pkt[1 + NONCE_PREFIX_LEN];
        pkt[0] = PKT_VER_HELLO;
        memcpy(pkt + 1, c->local_nonce_prefix, NONCE_PREFIX_LEN);
        return ac_send_packet(c, pkt, (int)sizeof(pkt));
    }
}
static int handle_hello(AudioCall *c, const uint8_t *buf, size_t len) {
    if (len < 1 + NONCE_PREFIX_LEN) return -1;
    memcpy(c->remote_nonce_prefix, buf + 1, NONCE_PREFIX_LEN);
    atomic_store(&c->remote_prefix_ready, 1);

    /* Check for identity extension (only on first HELLO) */
    if (len >= HELLO_SIZE_SIGNED && c->peer_verified == 0) {
        uint8_t flags = buf[1 + NONCE_PREFIX_LEN];
        if (flags & HELLO_FLAG_IDENTITY) {
            const uint8_t *peer_pk = buf + 1 + NONCE_PREFIX_LEN + 1;
            const uint8_t *sig = peer_pk + IDENTITY_PK_BYTES;
            /* Verify signature over nonce_prefix */
            if (identity_verify(buf + 1, NONCE_PREFIX_LEN, sig, peer_pk) == 0) {
                memcpy(c->peer_identity_pk, peer_pk, IDENTITY_PK_BYTES);
                tofu_result_t tofu = identity_tofu_check(c->known_keys_path, "peer", peer_pk);
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(peer_pk, fp);
                if (tofu == TOFU_NEW_KEY) {
                    printf("[TOFU] New peer identity: %s\n", fp);
                    c->peer_verified = 1;
                } else if (tofu == TOFU_KEY_MATCH) {
                    printf("[VERIFIED] Peer identity: %s\n", fp);
                    c->peer_verified = 1;
                } else if (tofu == TOFU_KEY_CONFLICT) {
                    printf("[WARNING] PEER KEY CHANGED! Fingerprint: %s\n", fp);
                    c->peer_verified = -1;
                }
                fflush(stdout);
            } else {
                printf("[!] Peer identity signature verification failed\n");
                fflush(stdout);
                c->peer_verified = -1;
            }
        }
    } else if (len == 1 + NONCE_PREFIX_LEN) {
        /* Old-style unsigned HELLO */
        c->peer_verified = 0;
    }
    return 0;
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
    if (inet_pton(AF_INET, ip, &srv.sin_addr) != 1) {
        fprintf(stderr, "TCP inet_pton failed for %s\n", ip);
        CLOSESOCK(c->tcp_sock); c->tcp_sock = 0;
        return -1;
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

        if (tcp_recv_all(c->tcp_sock, hdr2, 2) < 0) return -1;
        uint16_t room_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (room_len > 255) return -1;
        if (tcp_recv_all(c->tcp_sock, skip, room_len) < 0) return -1;

        if (tcp_recv_all(c->tcp_sock, hdr2, 2) < 0) return -1;
        uint16_t name_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (name_len > 255) return -1;
        if (tcp_recv_all(c->tcp_sock, skip, name_len) < 0) return -1;

        if (tcp_recv_all(c->tcp_sock, hdr2, 2) < 0) return -1;
        uint16_t nonce_len = (uint16_t)(hdr2[0] | (hdr2[1] << 8));
        if (nonce_len > sizeof(skip)) return -1;
        if (nonce_len > 0 && tcp_recv_all(c->tcp_sock, skip, nonce_len) < 0) return -1;

        uint8_t type;
        if (tcp_recv_all(c->tcp_sock, &type, 1) < 0) return -1;

        uint8_t clenbuf[4];
        if (tcp_recv_all(c->tcp_sock, clenbuf, 4) < 0) return -1;
        uint32_t clen = (uint32_t)(clenbuf[0] | (clenbuf[1] << 8) |
                                    (clenbuf[2] << 16) | (clenbuf[3] << 24));

        if (type == MSG_TYPE_MEDIA_RELAY && (int)clen <= out_size && clen > 0) {
            if (tcp_recv_all(c->tcp_sock, out, clen) < 0) return -1;
            return (int)clen;
        }

        uint32_t remaining = clen;
        while (remaining > 0) {
            uint32_t chunk = remaining > sizeof(skip) ? sizeof(skip) : remaining;
            if (tcp_recv_all(c->tcp_sock, skip, chunk) < 0) return -1;
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

/* Криптографические функции теперь в audio_crypto.h:
   - audio_encrypt_packet() - шифрование с sequence number
   - audio_decrypt_packet() - расшифровка с проверкой
*/

static int encrypt_opus(AudioCall *c, const uint8_t *opus, size_t opus_len,
                        uint8_t *out, size_t *out_len, uint64_t seq)
{
    return audio_encrypt_packet(opus, opus_len, c->key,
                                c->local_nonce_prefix, seq, out, out_len);
}

static int decrypt_opus(AudioCall *c, const uint8_t *pkt, size_t pkt_len,
                        uint8_t *opus_out, size_t *opus_len)
{
    if (!atomic_load(&c->remote_prefix_ready)) return -2;
    return audio_decrypt_packet(pkt, pkt_len, c->key,
                                c->remote_nonce_prefix, opus_out, opus_len);
}

/* ===== Stats packet: [0x04][seq(8 BE)][AES-GCM(16 bytes payload + 16 tag)] ===== */

typedef struct {
    uint32_t ping_ts;    /* sender's timestamp (lower 32 bits of ms) */
    uint32_t pong_ts;    /* echo of peer's last ping_ts */
    uint32_t reserved1;
    uint32_t reserved2;
} AudioStatsPayload;

static int encrypt_stats(AudioCall *c, const AudioStatsPayload *sp,
                          uint8_t *out, size_t *out_len, uint64_t seq) {
    out[0] = PKT_VER_STATS;
    uint64_t be_seq = htonll_u64(seq);
    memcpy(out + 1, &be_seq, 8);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, c->local_nonce_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, &be_seq, 8);

    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            out + 1 + 8, &clen,
            (const uint8_t *)sp, sizeof(AudioStatsPayload),
            NULL, 0, NULL, nonce, c->key) != 0) {
        return -1;
    }
    *out_len = 1 + 8 + (size_t)clen;
    return 0;
}

static int decrypt_stats(AudioCall *c, const uint8_t *pkt, size_t pkt_len,
                          AudioStatsPayload *sp_out) {
    if (pkt_len < 1 + 8 + AES_GCM_ABYTES) return -1;
    if (!atomic_load(&c->remote_prefix_ready)) return -2;

    uint64_t be_seq;
    memcpy(&be_seq, pkt + 1, 8);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, c->remote_nonce_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, &be_seq, 8);

    unsigned long long mlen = 0;
    uint8_t plain[64];
    if (crypto_aead_aes256gcm_decrypt(
            plain, &mlen, NULL,
            pkt + 1 + 8, pkt_len - (1 + 8),
            NULL, 0, nonce, c->key) != 0) {
        return -1;
    }
    if (mlen < sizeof(AudioStatsPayload)) return -1;
    memcpy(sp_out, plain, sizeof(AudioStatsPayload));
    return 0;
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

    int waited = 0;
    while (atomic_load(&c->running)) {
        if (atomic_load(&c->remote_prefix_ready)) break;
        if (waited == 0 && (c->peer_set || c->tcp_sock)) send_hello(c);
        waited++;
        msleep(50);
        if (waited % 20 == 0 && (c->peer_set || c->tcp_sock)) {
            /* Re-send UDP relay registration periodically (only for UDP relay) */
            if (c->relay_mode && !c->tcp_sock) send_udp_registration(c);
            send_hello(c);
        }
    }

    int16_t pcm[AC_FRAME_SAMPLES];
    uint8_t opus[AC_MAX_OPUS_BYTES];
    uint8_t packet[1 + 8 + AC_MAX_OPUS_BYTES + AES_GCM_ABYTES];

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

        int enc_bytes = opus_encode(c->enc, pcm, AC_FRAME_SAMPLES, opus, (opus_int32)sizeof(opus));
        if (enc_bytes < 0) {
            continue;
        }

        uint64_t seq = atomic_fetch_add(&c->seq_tx, 1);
        size_t pkt_len = 0;
        if (encrypt_opus(c, opus, (size_t)enc_bytes, packet, &pkt_len, seq) != 0) {
            continue;
        }

        ac_send_packet(c, packet, (int)pkt_len);

        /* Send stats every 2 seconds */
        uint64_t now = audio_time_ms();
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

            uint8_t stats_pkt[1 + 8 + sizeof(AudioStatsPayload) + AES_GCM_ABYTES];
            size_t stats_len = 0;
            uint64_t stats_seq = atomic_fetch_add(&c->seq_tx, 1);
            if (encrypt_stats(c, &sp, stats_pkt, &stats_len, stats_seq) == 0) {
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

static THREAD_RET th_recv_func(void *arg) {
    ThreadArgs *ta = (ThreadArgs*)arg;
    AudioCall *c = ta->c;
    free(ta);

    uint8_t rbuf[AC_UDP_RECV_BUFSZ];
    uint8_t opus[AC_MAX_OPUS_BYTES];
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

        if (rbuf[0] == PKT_VER_HELLO) {
            handle_hello(c, rbuf, (size_t)n);
            if (c->peer_set || c->tcp_sock) send_hello(c);
            continue;
        }

        /* Stats packet: RTT ping/pong */
        if (rbuf[0] == PKT_VER_STATS) {
            AudioStatsPayload sp;
            if (decrypt_stats(c, rbuf, (size_t)n, &sp) == 0) {
                if (sp.pong_ts != 0) {
                    uint32_t now32 = (uint32_t)(audio_time_ms() & 0xFFFFFFFF);
                    c->measured_rtt_ms = now32 - sp.pong_ts;
                }
                c->last_peer_ping_ts = sp.ping_ts;
                c->peer_ping_recv_time = audio_time_ms();
            }
            continue;
        }

        size_t opus_len = 0;
        if (decrypt_opus(c, rbuf, (size_t)n, opus, &opus_len) != 0) {
            continue;
        }

        int dec_samples = opus_decode(c->dec, opus, (opus_int32)opus_len,
                                      pcm, AC_FRAME_SAMPLES, 0);
        if (dec_samples <= 0) continue;
        if (dec_samples < AC_FRAME_SAMPLES) {
            memset(pcm + dec_samples * AC_CHANNELS, 0,
                   (AC_FRAME_SAMPLES - dec_samples) * AC_CHANNELS * sizeof(int16_t));
        }

        pcmring_push(&c->out_ring, pcm);

        /* Latency control: if buffer grows too large, drain old frames.
           Max ~20 frames (400ms) prevents unbounded latency accumulation
           that occurs with TCP relay bursts. */
        #define MAX_PLAYOUT_FRAMES 20
        while (atomic_load(&c->out_ring.count) > MAX_PLAYOUT_FRAMES) {
            int16_t discard[AC_FRAME_SAMPLES];
            pcmring_pop(&c->out_ring, discard);
        }

        // Воспроизводим только если выходной поток доступен и буфер достаточно наполнен
        if (c->out_stream && atomic_load(&c->out_ring.count) >= PLAYOUT_BUFFER_FRAMES) {
            int16_t play[AC_FRAME_SAMPLES];
            if (pcmring_pop(&c->out_ring, play) == 0) {
                Pa_WriteStream(c->out_stream, play, AC_FRAME_SAMPLES);
            }
        }
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
    opus_encoder_ctl(c->enc, OPUS_SET_BITRATE(AC_OPUS_BITRATE));
    opus_encoder_ctl(c->enc, OPUS_SET_COMPLEXITY(AC_OPUS_COMPLEXITY));
    opus_encoder_ctl(c->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    opus_encoder_ctl(c->enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(c->enc, OPUS_SET_PACKET_LOSS_PERC(10));

    c->dec = opus_decoder_create(AC_SAMPLE_RATE, AC_CHANNELS, &err);
    if (!c->dec || err != OPUS_OK) {
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
#else
    if (c->th_send) {
        pthread_join(c->th_send, NULL);
        c->th_send = 0;
    }
    if (c->th_recv) {
        pthread_join(c->th_recv, NULL);
        c->th_recv = 0;
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
    if (c->dec) {
        opus_decoder_destroy(c->dec);
        c->dec = NULL;
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

    pcmring_free(&c->out_ring);
    free(c);
}

int audio_call_start(AudioCall **out_call,
                     const char *remote_ip, uint16_t remote_port,
                     uint16_t bind_port,
                     int is_caller,
                     const uint8_t key[AES_GCM_KEY_LEN],
                     int input_device_id,
                     int output_device_id,
                     const uint8_t *id_pk,
                     const uint8_t *id_sk,
                     int relay_mode,
                     const char *relay_room,
                     const char *relay_name)
{
    if (!out_call || !key) return -1;
    if (net_init_once() != 0) return -1;
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return -1;
    }

    AudioCall *c = (AudioCall*)calloc(1, sizeof(AudioCall));
    if (!c) return -1;
    memcpy(c->key, key, AES_GCM_KEY_LEN);
    randombytes_buf(c->local_nonce_prefix, NONCE_PREFIX_LEN);
    atomic_store(&c->remote_prefix_ready, 0);
    atomic_store(&c->seq_tx, 0);
    atomic_store(&c->running, 1);

    /* Initialize identity */
    if (id_pk && id_sk) {
        c->has_identity = 1;
        memcpy(c->identity_pk, id_pk, IDENTITY_PK_BYTES);
        memcpy(c->identity_sk, id_sk, IDENTITY_SK_BYTES);
    } else {
        c->has_identity = 0;
    }
    c->peer_verified = 0;
    identity_default_known_keys_path(c->known_keys_path, sizeof(c->known_keys_path));

    /* Relay mode setup */
    c->relay_mode = relay_mode;
    if (relay_mode && relay_room && relay_name) {
        strncpy(c->relay_room, relay_room, sizeof(c->relay_room) - 1);
        c->relay_room[sizeof(c->relay_room) - 1] = '\0';
        strncpy(c->relay_name, relay_name, sizeof(c->relay_name) - 1);
        c->relay_name[sizeof(c->relay_name) - 1] = '\0';
    } else {
        c->relay_mode = 0;
        c->relay_room[0] = '\0';
        c->relay_name[0] = '\0';
    }

    if (pcmring_init(&c->out_ring, 128) != 0) {
        free(c);
        return -1;
    }

    c->sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (c->sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "socket() failed\n");
        pcmring_free(&c->out_ring);
        free(c);
        return -1;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(bind_port);
    if (bind(c->sock, (struct sockaddr*)&local, sizeof(local)) == SOCK_ERR) {
        fprintf(stderr, "bind() failed (port %u)\n", bind_port);
        CLOSESOCK(c->sock);
        pcmring_free(&c->out_ring);
        free(c);
        return -1;
    }

    c->peer_set = 0;
    if (remote_ip && remote_port != 0) {
        memset(&c->peer, 0, sizeof(c->peer));
        c->peer.sin_family = AF_INET;
        c->peer.sin_port = htons(remote_port);
        if (inet_pton(AF_INET, remote_ip, &c->peer.sin_addr) != 1) {
            fprintf(stderr, "inet_pton failed for %s\n", remote_ip);
            CLOSESOCK(c->sock);
            pcmring_free(&c->out_ring);
            free(c);
            return -1;
        }
        c->peer_set = 1;
    }

    if (audio_init_ports(c, input_device_id, output_device_id) != 0) {
        CLOSESOCK(c->sock);
        pcmring_free(&c->out_ring);
        free(c);
        return -1;
    }
    if (audio_init_codec(c) != 0) {
        Pa_Terminate();
        CLOSESOCK(c->sock);
        pcmring_free(&c->out_ring);
        free(c);
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
            pcmring_free(&c->out_ring); free(c);
            return -1;
        }
        if (tcp_relay_register(c) != 0) {
            fprintf(stderr, "TCP relay registration failed\n");
            CLOSESOCK(c->tcp_sock); Pa_Terminate(); CLOSESOCK(c->sock);
            pcmring_free(&c->out_ring); free(c);
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
        if (c->dec) opus_decoder_destroy(c->dec);
        Pa_Terminate();
        CLOSESOCK(c->sock);
        pcmring_free(&c->out_ring);
        free(c);
        return -1;
    }
    a1->c = c; a2->c = c;

#ifdef _WIN32
    c->th_recv = CreateThread(NULL, 0, th_recv_func, a1, 0, NULL);
    c->th_send = CreateThread(NULL, 0, th_send_func, a2, 0, NULL);
    if (!c->th_recv || !c->th_send) {
        audio_call_stop(c);
        return -1;
    }
#else
    if (pthread_create(&c->th_recv, NULL, th_recv_func, a1) != 0 ||
        pthread_create(&c->th_send, NULL, th_send_func, a2) != 0) {
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
    if (argc < 2) {
        fprintf(stderr,
                "Usage:\n"
                "  %s genkey\n"
                "  %s listdevices\n"
                "  %s call <remote_ip> <remote_port> [--key-file FILE] [local_bind_port] [input_dev] [output_dev]\n"
                "  %s listen <local_bind_port> [--key-file FILE] [input_dev] [output_dev]\n"
                "  %s hub <bind_port>\n"
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
            fprintf(stderr, "Usage: %s call <remote_ip> <remote_port> [--key-file FILE] [--identity-file FILE] [--no-sign] [local_bind_port] [input_dev] [output_dev]\n", argv[0]);
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
        if (audio_call_start(&call, ip, rport, lport, 1, key, input_dev, output_dev,
                             has_identity ? id_pk : NULL,
                             has_identity ? id_sk : NULL,
                             0, NULL, NULL) != 0) {
            fprintf(stderr, "Failed to start call\n");
            if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
            return 1;
        }
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));

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
            fprintf(stderr, "Usage: %s listen <local_bind_port> [--key-file FILE] [--identity-file FILE] [--no-sign] [input_dev] [output_dev]\n", argv[0]);
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
        if (audio_call_start(&call, NULL, 0, lport, 0, key, input_dev, output_dev,
                             has_identity ? id_pk : NULL,
                             has_identity ? id_sk : NULL,
                             0, NULL, NULL) != 0) {
            fprintf(stderr, "Failed to start listener\n");
            if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
            return 1;
        }
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));

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
            fprintf(stderr, "Usage: %s relay <server_ip> <server_port> --room ROOM --name NAME [--key-file FILE] [--identity-file FILE] [--no-sign] [input_dev] [output_dev]\n", argv[0]);
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
        if (audio_call_start(&call, ip, rport, 0, 1, key, input_dev, output_dev,
                             has_identity ? id_pk : NULL,
                             has_identity ? id_sk : NULL,
                             1, relay_room, relay_name) != 0) {
            fprintf(stderr, "Failed to start relay call\n");
            if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));
            return 1;
        }
        if (has_identity) sodium_memzero(id_sk, sizeof(id_sk));

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