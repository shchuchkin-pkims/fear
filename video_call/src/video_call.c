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
#  include <pthread.h>
#  define THREAD_RET void*
#endif

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

/* ===== VideoCall state ===== */

typedef struct VideoCall {
    socket_t sock;
    struct sockaddr_in peer;
    int peer_set;

    /* Master key and derived sub-keys */
    uint8_t master_key[AES_GCM_KEY_LEN];
    uint8_t audio_key[AES_GCM_KEY_LEN];
    uint8_t video_key[AES_GCM_KEY_LEN];

    uint8_t local_nonce_prefix[NONCE_PREFIX_LEN];
    uint8_t remote_nonce_prefix[NONCE_PREFIX_LEN];
    atomic_int remote_prefix_ready;

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
    if (inet_pton(AF_INET, ip, &srv.sin_addr) != 1) {
        fprintf(stderr, "TCP inet_pton failed for %s\n", ip);
        CLOSESOCK(vc->tcp_sock); vc->tcp_sock = 0;
        return -1;
    }
    if (connect(vc->tcp_sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        fprintf(stderr, "TCP connect failed to %s:%u\n", ip, port);
        CLOSESOCK(vc->tcp_sock); vc->tcp_sock = 0;
        return -1;
    }
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

        if (type == MSG_TYPE_MEDIA_RELAY && (int)clen <= out_size && clen > 0) {
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

/* ===== Key derivation ===== */

static int derive_subkeys(VideoCall *vc) {
    if (crypto_kdf_derive_from_key(vc->audio_key, AES_GCM_KEY_LEN,
                                    KDF_SUBKEY_AUDIO, KDF_CONTEXT_AUDIO,
                                    vc->master_key) != 0) {
        fprintf(stderr, "KDF failed for audio sub-key\n");
        return -1;
    }
    if (crypto_kdf_derive_from_key(vc->video_key, AES_GCM_KEY_LEN,
                                    KDF_SUBKEY_VIDEO, KDF_CONTEXT_VIDEO,
                                    vc->master_key) != 0) {
        fprintf(stderr, "KDF failed for video sub-key\n");
        return -1;
    }
    return 0;
}

/* ===== HELLO handshake ===== */

static int send_hello(VideoCall *vc) {
    /* Max HELLO size: HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES = 107 */
    uint8_t pkt[HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES];
    pkt[0] = PKT_TYPE_HELLO;
    memcpy(pkt + 1, vc->local_nonce_prefix, NONCE_PREFIX_LEN);

    int pkt_len;
    if (vc->video_enabled) {
        uint8_t flags = 0;
        if (vc->video_enabled) flags |= HELLO_FLAG_VIDEO;
        if (vc->audio_enabled) flags |= HELLO_FLAG_AUDIO;
        if (vc->has_identity) flags |= HELLO_FLAG_IDENTITY;
        pkt[5] = flags;

        const VideoQualityPreset *preset = quality_get_preset(&vc->quality);
        uint16_t w = htons((uint16_t)preset->width);
        uint16_t h = htons((uint16_t)preset->height);
        memcpy(pkt + 6, &w, 2);
        memcpy(pkt + 8, &h, 2);
        pkt[10] = (uint8_t)preset->fps;
        pkt_len = HELLO_SIZE_VIDEO;

        if (vc->has_identity) {
            memcpy(pkt + pkt_len, vc->identity_pk, IDENTITY_PK_BYTES);
            /* Sign all preceding HELLO bytes */
            identity_sign(pkt, (size_t)pkt_len + IDENTITY_PK_BYTES, vc->identity_sk,
                          pkt + pkt_len + IDENTITY_PK_BYTES);
            pkt_len += IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES;
        }
    } else {
        if (vc->has_identity) {
            /* Audio-only signed: [0x7F][prefix(4)][flags(1)][pk(32)][sig(64)] */
            pkt[5] = HELLO_FLAG_AUDIO | HELLO_FLAG_IDENTITY;
            pkt_len = 6;
            memcpy(pkt + pkt_len, vc->identity_pk, IDENTITY_PK_BYTES);
            identity_sign(pkt, (size_t)pkt_len + IDENTITY_PK_BYTES, vc->identity_sk,
                          pkt + pkt_len + IDENTITY_PK_BYTES);
            pkt_len += IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES;
        } else {
            pkt_len = HELLO_SIZE_AUDIO;
        }
    }

    return vc_send_packet(vc, pkt, pkt_len);
}

static int handle_hello(VideoCall *vc, const uint8_t *buf, size_t len) {
    if (len < HELLO_SIZE_AUDIO) {
        fprintf(stderr, "[handle_hello] REJECTED: len=%zu < HELLO_SIZE_AUDIO=%d\n",
                len, HELLO_SIZE_AUDIO);
        return -1;
    }
    fprintf(stderr, "[handle_hello] OK: len=%zu, setting remote_prefix_ready=1\n", len);

    /* Detect if peer reconnected (different nonce prefix = new session) */
    int prefix_changed = (atomic_load(&vc->remote_prefix_ready) &&
                          memcmp(vc->remote_nonce_prefix, buf + 1, NONCE_PREFIX_LEN) != 0);

    memcpy(vc->remote_nonce_prefix, buf + 1, NONCE_PREFIX_LEN);
    atomic_store(&vc->remote_prefix_ready, 1);
    atomic_store(&vc->last_recv_time, video_time_ms());
    atomic_store(&vc->peer_connected, 1);

    if (prefix_changed) {
        printf("Peer reconnected, resetting state\n");
        /* Reset fragment receiver for new session */
        video_frag_receiver_free(&vc->frag_recv);
        video_frag_receiver_init(&vc->frag_recv);
        /* Reset decoder for clean keyframe */
        if (vc->v_dec) {
            video_decoder_close(vc->v_dec);
            vc->v_dec = NULL;
            video_decoder_open(&vc->v_dec);
        }
        /* Clear stale display frame */
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
        /* Force peer params to 0 so they get re-logged below */
        vc->peer_width = 0;
        vc->peer_height = 0;
        vc->peer_fps = 0;
        vc->peer_video_enabled = 0;
    }

    if (len >= HELLO_SIZE_VIDEO) {
        uint8_t flags = buf[5];
        int new_video = (flags & HELLO_FLAG_VIDEO) ? 1 : 0;

        uint16_t w, h;
        memcpy(&w, buf + 6, 2);
        memcpy(&h, buf + 8, 2);
        int new_w = ntohs(w);
        int new_h = ntohs(h);
        int new_fps = buf[10];

        /* Only log when peer video params change */
        if (new_w != vc->peer_width || new_h != vc->peer_height ||
            new_fps != vc->peer_fps || new_video != vc->peer_video_enabled) {
            printf("Peer video: %dx%d @ %d fps\n", new_w, new_h, new_fps);
        }

        vc->peer_video_enabled = new_video;
        vc->peer_width = new_w;
        vc->peer_height = new_h;
        vc->peer_fps = new_fps;

        /* Check for identity extension in video HELLO (only on first HELLO) */
        if (vc->peer_verified == 0 &&
            (flags & HELLO_FLAG_IDENTITY) &&
            len >= HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) {
            const uint8_t *peer_pk = buf + HELLO_SIZE_VIDEO;
            const uint8_t *sig = peer_pk + IDENTITY_PK_BYTES;
            /* Verify: signature covers [0x7F..fps][pk] = first HELLO_SIZE_VIDEO + PK bytes */
            if (identity_verify(buf, HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES, sig, peer_pk) == 0) {
                memcpy(vc->peer_identity_pk, peer_pk, IDENTITY_PK_BYTES);
                tofu_result_t tofu = identity_tofu_check(vc->known_keys_path, "peer", peer_pk);
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(peer_pk, fp);
                if (tofu == TOFU_NEW_KEY) {
                    printf("[TOFU] New peer identity: %s\n", fp);
                    vc->peer_verified = 1;
                } else if (tofu == TOFU_KEY_MATCH) {
                    printf("[VERIFIED] Peer identity: %s\n", fp);
                    vc->peer_verified = 1;
                } else if (tofu == TOFU_KEY_CONFLICT) {
                    printf("[WARNING] PEER KEY CHANGED! Fingerprint: %s\n", fp);
                    vc->peer_verified = -1;
                }
                fflush(stdout);
            } else {
                printf("[!] Peer identity signature verification failed\n");
                fflush(stdout);
                vc->peer_verified = -1;
            }
        }
    } else if (len >= 6) {
        /* Audio-only with flags byte: [0x7F][prefix(4)][flags(1)]... */
        uint8_t flags = buf[5];
        if (vc->peer_video_enabled != 0) {
            printf("Peer is audio-only\n");
        }
        vc->peer_video_enabled = 0;

        /* Check for identity in audio-only HELLO with flags (only on first HELLO) */
        if (vc->peer_verified == 0 &&
            (flags & HELLO_FLAG_IDENTITY) &&
            len >= 6 + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES) {
            const uint8_t *peer_pk = buf + 6;
            const uint8_t *sig = peer_pk + IDENTITY_PK_BYTES;
            if (identity_verify(buf, 6 + IDENTITY_PK_BYTES, sig, peer_pk) == 0) {
                memcpy(vc->peer_identity_pk, peer_pk, IDENTITY_PK_BYTES);
                tofu_result_t tofu = identity_tofu_check(vc->known_keys_path, "peer", peer_pk);
                char fp[IDENTITY_FINGERPRINT_LEN];
                identity_pk_fingerprint(peer_pk, fp);
                if (tofu == TOFU_NEW_KEY) {
                    printf("[TOFU] New peer identity: %s\n", fp);
                    vc->peer_verified = 1;
                } else if (tofu == TOFU_KEY_MATCH) {
                    printf("[VERIFIED] Peer identity: %s\n", fp);
                    vc->peer_verified = 1;
                } else if (tofu == TOFU_KEY_CONFLICT) {
                    printf("[WARNING] PEER KEY CHANGED! Fingerprint: %s\n", fp);
                    vc->peer_verified = -1;
                }
                fflush(stdout);
            }
        }
    } else {
        if (vc->peer_video_enabled != 0) {
            printf("Peer is audio-only\n");
        }
        vc->peer_video_enabled = 0;
    }

    return 0;
}

/* ===== Encryption helpers ===== */

static int encrypt_audio_pkt(VideoCall *vc, const uint8_t *opus, size_t opus_len,
                              uint8_t *out, size_t *out_len, uint64_t seq) {
    return audio_encrypt_packet(opus, opus_len, vc->audio_key,
                                vc->local_nonce_prefix, seq, out, out_len);
}

static int encrypt_video_frag(VideoCall *vc, const uint8_t *frag, size_t frag_len,
                               uint8_t *out, size_t *out_len, uint64_t seq) {
    /* Packet format: [0x02][seq(8)][AES-GCM(frag_header+vp8_data)+tag(16)] */
    out[0] = PKT_TYPE_VIDEO_FRAG;
    uint64_t be_seq = htonll_u64(seq);
    memcpy(out + 1, &be_seq, 8);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, vc->local_nonce_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, &be_seq, 8);

    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            out + 1 + 8, &clen,
            frag, frag_len,
            NULL, 0, NULL, nonce, vc->video_key) != 0) {
        return -1;
    }

    *out_len = 1 + 8 + (size_t)clen;
    return 0;
}

static int decrypt_video_frag(VideoCall *vc, const uint8_t *pkt, size_t pkt_len,
                               uint8_t *frag_out, size_t *frag_len) {
    if (pkt_len < 1 + 8 + AES_GCM_ABYTES) return -1;
    if (pkt[0] != PKT_TYPE_VIDEO_FRAG) return -1;

    uint64_t be_seq;
    memcpy(&be_seq, pkt + 1, 8);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, vc->remote_nonce_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, &be_seq, 8);

    unsigned long long mlen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            frag_out, &mlen, NULL,
            pkt + 1 + 8, pkt_len - (1 + 8),
            NULL, 0, nonce, vc->video_key) != 0) {
        return -1;
    }

    *frag_len = (size_t)mlen;
    return 0;
}

static int encrypt_stats(VideoCall *vc, const StatsPayload *stats,
                          uint8_t *out, size_t *out_len, uint64_t seq) {
    out[0] = PKT_TYPE_STATS;
    uint64_t be_seq = htonll_u64(seq);
    memcpy(out + 1, &be_seq, 8);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, vc->local_nonce_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, &be_seq, 8);

    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            out + 1 + 8, &clen,
            (const uint8_t *)stats, sizeof(StatsPayload),
            NULL, 0, NULL, nonce, vc->video_key) != 0) {
        return -1;
    }

    *out_len = 1 + 8 + (size_t)clen;
    return 0;
}

static int decrypt_stats(VideoCall *vc, const uint8_t *pkt, size_t pkt_len,
                          StatsPayload *stats_out) {
    if (pkt_len < 1 + 8 + AES_GCM_ABYTES) return -1;

    uint64_t be_seq;
    memcpy(&be_seq, pkt + 1, 8);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, vc->remote_nonce_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, &be_seq, 8);

    unsigned long long mlen = 0;
    uint8_t plain[64];
    if (crypto_aead_aes256gcm_decrypt(
            plain, &mlen, NULL,
            pkt + 1 + 8, pkt_len - (1 + 8),
            NULL, 0, nonce, vc->video_key) != 0) {
        return -1;
    }

    if (mlen < sizeof(StatsPayload)) return -1;
    memcpy(stats_out, plain, sizeof(StatsPayload));
    return 0;
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
    /* Max encrypted fragment: 1 + 8 + FRAG_HEADER_SIZE + FRAG_MAX_PAYLOAD + 16 */
    uint8_t enc_buf[1 + 8 + FRAG_HEADER_SIZE + FRAG_MAX_PAYLOAD + AES_GCM_ABYTES];
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

    /* Wait for handshake while continuously draining camera frames.
       Without this, dshow buffer fills up during handshake and all new frames get dropped. */
    while (atomic_load(&vc->running)) {
        if (atomic_load(&vc->remote_prefix_ready)) break;
        /* Keep reading frames to prevent dshow buffer overflow */
        video_capture_read(vc->capture, yuv_buf, yuv_size);
    }

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

        /* Capture frame */
        int cap_ret = video_capture_read(vc->capture, yuv_buf, yuv_size);
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
                                    enc_buf, &enc_len, seq) != 0) {
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
            uint64_t seq = atomic_fetch_add(&vc->video_seq_tx, 1);
            size_t enc_len = 0;
            if (encrypt_stats(vc, &sp, enc_buf, &enc_len, seq) == 0) {
                vc_send_packet(vc, enc_buf, (int)enc_len);
            }
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

    /* Wait for handshake */
    int waited = 0;
    while (atomic_load(&vc->running)) {
        if (atomic_load(&vc->remote_prefix_ready)) break;
        if (waited == 0 && (vc->peer_set || vc->tcp_sock)) send_hello(vc);
        waited++;
        msleep(50);
        if (waited % 20 == 0 && (vc->peer_set || vc->tcp_sock)) {
            /* Re-send UDP relay registration periodically (only for UDP relay) */
            if (vc->relay_mode && !vc->tcp_sock) send_udp_registration(vc);
            send_hello(vc);
        }
    }

    if (!vc->audio_enabled) {
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    int16_t pcm[VC_FRAME_SAMPLES];
    uint8_t opus_buf[VC_MAX_OPUS_BYTES];
    uint8_t packet[1 + 8 + VC_MAX_OPUS_BYTES + AES_GCM_ABYTES];

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
                               packet, &pkt_len, seq) != 0) {
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

        /* HELLO handshake */
        if (pkt_type == PKT_TYPE_HELLO) {
            handle_hello(vc, rbuf, (size_t)n);
            if (vc->peer_set || vc->tcp_sock) send_hello(vc);
            continue;
        }

        if (!atomic_load(&vc->remote_prefix_ready)) continue;

        /* Update last receive time for peer timeout detection */
        atomic_store(&vc->last_recv_time, video_time_ms());
        atomic_store(&vc->peer_connected, 1);

        /* Audio packet */
        if (pkt_type == PKT_TYPE_AUDIO && vc->audio_enabled) {
            size_t opus_len = 0;
            if (audio_decrypt_packet(rbuf, (size_t)n, vc->audio_key,
                                      vc->remote_nonce_prefix,
                                      opus_buf, &opus_len) != 0) {
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
            if (decrypt_video_frag(vc, rbuf, (size_t)n, dec_buf, &frag_len) != 0) {
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

        /* Stats packet */
        if (pkt_type == PKT_TYPE_STATS) {
            StatsPayload sp;
            if (decrypt_stats(vc, rbuf, (size_t)n, &sp) == 0) {
                quality_record_peer_stats(&vc->quality, sp.packets_received, sp.packets_lost);
                quality_update(&vc->quality, &sp, video_time_ms());
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

    /* Secure wipe keys */
    sodium_memzero(vc->master_key, sizeof(vc->master_key));
    sodium_memzero(vc->audio_key, sizeof(vc->audio_key));
    sodium_memzero(vc->video_key, sizeof(vc->video_key));

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
        if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) {
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
    if (net_init_once() != 0) return -1;
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return -1; }

    /* Initialize SDL3 */
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return -1;
    }

    VideoCall *vc = (VideoCall *)calloc(1, sizeof(VideoCall));
    if (!vc) return -1;

    /* Resolve key and derive sub-keys */
    if (resolve_key(opts, vc->master_key) != 0) { free(vc); SDL_Quit(); return -1; }
    if (derive_subkeys(vc) != 0) { free(vc); SDL_Quit(); return -1; }

    randombytes_buf(vc->local_nonce_prefix, NONCE_PREFIX_LEN);
    atomic_store(&vc->remote_prefix_ready, 0);
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
        if (inet_pton(AF_INET, remote_ip, &vc->peer.sin_addr) != 1) {
            fprintf(stderr, "inet_pton failed for %s\n", remote_ip);
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
    while (!atomic_load(&g_sigint) && atomic_load(&vc->running)) {
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
