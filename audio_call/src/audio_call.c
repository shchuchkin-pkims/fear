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
#else
#  include <unistd.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <sys/types.h>
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

/* -------------------------- Конфигурация --------------------------------- */

#define AC_SAMPLE_RATE       48000
#define AC_CHANNELS          1
#define AC_FRAME_MS          20
#define AC_FRAME_SAMPLES     ((AC_SAMPLE_RATE/1000)*AC_FRAME_MS) /* 960 */
#define AC_APP               OPUS_APPLICATION_VOIP
#define AC_OPUS_BITRATE      24000
#define AC_OPUS_COMPLEXITY   5
#define AC_UDP_RECV_BUFSZ    1500
#define AC_MAX_OPUS_BYTES    1275
#define AC_PCM_BYTES_PER_FR  (AC_FRAME_SAMPLES * sizeof(int16_t) * AC_CHANNELS)

/* Пакеты протокола */
#define PKT_VER_AUDIO  0x01
#define PKT_VER_HELLO  0x7F

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

static uint64_t htonll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) | htonl((uint32_t)(v >> 32));
#else
    return v;
#endif
}
static uint64_t ntohll_u64(uint64_t v) {
    return htonll_u64(v);
}

static void msleep(unsigned ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000UL;
    nanosleep(&ts, NULL);
#endif
}

/* --------------------- Кольцевой буфер PCM ------------------------------- */

typedef struct {
    int16_t *buf;
    size_t frames_cap;
    size_t rd, wr;
    atomic_size_t count;
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} PcmRing;

static int pcmring_init(PcmRing *r, size_t frames_cap) {
    memset(r, 0, sizeof(*r));
    r->frames_cap = frames_cap;
    r->buf = (int16_t*)malloc(frames_cap * AC_FRAME_SAMPLES * sizeof(int16_t));
    if (!r->buf) return -1;
#ifdef _WIN32
    InitializeCriticalSection(&r->lock);
#else
    pthread_mutex_init(&r->lock, NULL);
#endif
    atomic_init(&r->count, 0);
    r->rd = r->wr = 0;
    return 0;
}
static void pcmring_free(PcmRing *r) {
    if (!r) return;
    if (r->buf) free(r->buf);
#ifdef _WIN32
    DeleteCriticalSection(&r->lock);
#else
    pthread_mutex_destroy(&r->lock);
#endif
    memset(r, 0, sizeof(*r));
}
static int pcmring_push(PcmRing *r, const int16_t *frame) {
#ifdef _WIN32
    EnterCriticalSection(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif
    if (atomic_load(&r->count) == r->frames_cap) {
        r->rd = (r->rd + 1) % r->frames_cap;
        atomic_fetch_sub(&r->count, 1);
    }
    memcpy(&r->buf[r->wr * AC_FRAME_SAMPLES], frame, AC_PCM_BYTES_PER_FR);
    r->wr = (r->wr + 1) % r->frames_cap;
    atomic_fetch_add(&r->count, 1);
#ifdef _WIN32
    LeaveCriticalSection(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif
    return 0;
}
static int pcmring_pop(PcmRing *r, int16_t *out_frame) {
    if (atomic_load(&r->count) == 0) return -1;
#ifdef _WIN32
    EnterCriticalSection(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif
    if (atomic_load(&r->count) == 0) {
#ifdef _WIN32
        LeaveCriticalSection(&r->lock);
#else
        pthread_mutex_unlock(&r->lock);
#endif
        return -1;
    }
    memcpy(out_frame, &r->buf[r->rd * AC_FRAME_SAMPLES], AC_PCM_BYTES_PER_FR);
    r->rd = (r->rd + 1) % r->frames_cap;
    atomic_fetch_sub(&r->count, 1);
#ifdef _WIN32
    LeaveCriticalSection(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif
    return 0;
}

/* --------------------------- Состояние звонка ---------------------------- */

typedef struct AudioCall {
    socket_t sock;
    struct sockaddr_in peer;
    int peer_set;

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

static int net_init_once(void) {
#ifdef _WIN32
    static atomic_int did = 0;
    if (atomic_exchange(&did, 1) == 0) {
        WSADATA w;
        if (WSAStartup(MAKEWORD(2,2), &w) != 0) return -1;
    }
#else
    (void)0;
#endif
    return 0;
}

/* ------------------------- HELLO handshake -------------------------------- */

static int send_hello(AudioCall *c) {
    uint8_t pkt[1 + NONCE_PREFIX_LEN];
    pkt[0] = PKT_VER_HELLO;
    memcpy(pkt + 1, c->local_nonce_prefix, NONCE_PREFIX_LEN);
    int r = sendto(c->sock, (const char*)pkt, (int)sizeof(pkt), 0,
                   (struct sockaddr*)&c->peer, sizeof(c->peer));
    return (r == (int)sizeof(pkt)) ? 0 : -1;
}
static int handle_hello(AudioCall *c, const uint8_t *buf, size_t len) {
    if (len != 1 + NONCE_PREFIX_LEN) return -1;
    memcpy(c->remote_nonce_prefix, buf + 1, NONCE_PREFIX_LEN);
    atomic_store(&c->remote_prefix_ready, 1);
    return 0;
}

/* --------------------------- AEAD-helpers -------------------------------- */

static void make_nonce(uint8_t out[AES_GCM_NONCE_LEN],
                       const uint8_t prefix[NONCE_PREFIX_LEN],
                       uint64_t seq)
{
    memcpy(out, prefix, NONCE_PREFIX_LEN);
    uint64_t be = htonll_u64(seq);
    memcpy(out + NONCE_PREFIX_LEN, &be, sizeof(be));
}

static int encrypt_opus(AudioCall *c, const uint8_t *opus, size_t opus_len,
                        uint8_t *out, size_t *out_len, uint64_t seq)
{
    uint8_t nonce[AES_GCM_NONCE_LEN];
    make_nonce(nonce, c->local_nonce_prefix, seq);

    out[0] = PKT_VER_AUDIO;
    uint64_t be = htonll_u64(seq);
    memcpy(out + 1, &be, sizeof(be));

    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            out + 1 + sizeof(be), &clen,
            opus, opus_len,
            NULL, 0,
            NULL, nonce, c->key) != 0) return -1;

    *out_len = 1 + sizeof(be) + (size_t)clen;
    return 0;
}

static int decrypt_opus(AudioCall *c, const uint8_t *pkt, size_t pkt_len,
                        uint8_t *opus_out, size_t *opus_len)
{
    if (pkt_len < 1 + 8 + AES_GCM_ABYTES) return -1;
    if (pkt[0] != PKT_VER_AUDIO) return -1;

    if (!atomic_load(&c->remote_prefix_ready)) return -2;

    uint64_t be_seq;
    memcpy(&be_seq, pkt + 1, 8);
    uint64_t seq = ntohll_u64(be_seq);

    uint8_t nonce[AES_GCM_NONCE_LEN];
    make_nonce(nonce, c->remote_nonce_prefix, seq);

    unsigned long long mlen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            opus_out, &mlen,
            NULL,
            pkt + 1 + 8, pkt_len - (1 + 8),
            NULL, 0, nonce, c->key) != 0) {
        return -1;
    }
    *opus_len = (size_t)mlen;
    return 0;
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
        if (waited == 0 && c->peer_set) send_hello(c);
        waited++;
        msleep(50);
        if (waited % 20 == 0 && c->peer_set) send_hello(c);
    }

    int16_t pcm[AC_FRAME_SAMPLES];
    uint8_t opus[AC_MAX_OPUS_BYTES];
    uint8_t packet[1 + 8 + AC_MAX_OPUS_BYTES + AES_GCM_ABYTES];

    while (atomic_load(&c->running)) {
        // Если входной поток недоступен, отправляем тишину
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

        if (c->peer_set) {
            sendto(c->sock, (const char*)packet, (int)pkt_len, 0,
                   (struct sockaddr*)&c->peer, sizeof(c->peer));
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
        struct sockaddr_in src;
#ifdef _WIN32
        int slen = sizeof(src);
#else
        socklen_t slen = sizeof(src);
#endif
        int n = recvfrom(c->sock, (char*)rbuf, (int)sizeof(rbuf), 0,
                         (struct sockaddr*)&src, &slen);
        if (n <= 0) {
            msleep(2);
            continue;
        }

        if (!c->peer_set) {
            c->peer = src;
            c->peer_set = 1;
        }

        if (rbuf[0] == PKT_VER_HELLO) {
            handle_hello(c, rbuf, (size_t)n);
            if (c->peer_set) send_hello(c);
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

        // Воспроизводим только если выходной поток доступен
        if (c->out_stream) {
            int16_t play[AC_FRAME_SAMPLES];
            while (atomic_load(&c->running) && atomic_load(&c->out_ring.count) > 0) {
                if (pcmring_pop(&c->out_ring, play) == 0) {
                    PaError pe = Pa_WriteStream(c->out_stream, play, AC_FRAME_SAMPLES);
                    if (pe == paOutputUnderflowed) break;
                    if (pe != paNoError) break;
                } else break;
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

static int audio_init_ports(AudioCall *c) {
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

    inParams.device = Pa_GetDefaultInputDevice();
    if (inParams.device != paNoDevice) {
        const PaDeviceInfo* indev = Pa_GetDeviceInfo(inParams.device);
        printf("Input device: %s\n", indev->name);
        inParams.channelCount = AC_CHANNELS;
        inParams.sampleFormat = paInt16;
        inParams.suggestedLatency = indev->defaultLowInputLatency;
        inParams.hostApiSpecificStreamInfo = NULL;
    }

    outParams.device = Pa_GetDefaultOutputDevice();
    if (outParams.device != paNoDevice) {
        const PaDeviceInfo* outdev = Pa_GetDeviceInfo(outParams.device);
        printf("Output device: %s\n", outdev->name);
        outParams.channelCount = AC_CHANNELS;
        outParams.sampleFormat = paInt16;
        outParams.suggestedLatency = outdev->defaultLowOutputLatency;
        outParams.hostApiSpecificStreamInfo = NULL;
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
    if (c->th_send) { WaitForSingleObject(c->th_send, INFINITE); CloseHandle(c->th_send); }
    if (c->th_recv) { WaitForSingleObject(c->th_recv, INFINITE); CloseHandle(c->th_recv); }
#else
    if (c->th_send) pthread_join(c->th_send, NULL);
    if (c->th_recv) pthread_join(c->th_recv, NULL);
#endif

    if (c->in_stream) { 
        Pa_StopStream(c->in_stream); 
        Pa_CloseStream(c->in_stream); 
    }
    if (c->out_stream){ 
        Pa_StopStream(c->out_stream); 
        Pa_CloseStream(c->out_stream); 
    }
    Pa_Terminate();

    if (c->enc) opus_encoder_destroy(c->enc);
    if (c->dec) opus_decoder_destroy(c->dec);

    if (c->sock) CLOSESOCK(c->sock);

    pcmring_free(&c->out_ring);
    free(c);
}

int audio_call_start(AudioCall **out_call,
                     const char *remote_ip, uint16_t remote_port,
                     uint16_t bind_port,
                     int is_caller,
                     const uint8_t key[AES_GCM_KEY_LEN])
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

    if (audio_init_ports(c) != 0) {
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

    if (is_caller && c->peer_set) {
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

static int hex2bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hlen = strlen(hex);
    if (hlen != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", b[i]);
    printf("\n");
}

/* ------------------------------- HUB (ретранслятор) --------------------- */

typedef struct {
    struct sockaddr_in addr;
    time_t last_seen;
    int used;
} HubClient;

typedef struct {
    socket_t sock;
    HubClient clients[HUB_MAX_CLIENTS];
    atomic_int running;
#ifdef _WIN32
    HANDLE th;
#else
    pthread_t th;
#endif
} Hub;

static void hub_init(Hub *h, socket_t sock) {
    memset(h, 0, sizeof(*h));
    h->sock = sock;
    atomic_store(&h->running, 1);
}

static int hub_find_or_add(Hub *h, const struct sockaddr_in *src) {
    /* Найти клиента по адресу, если нет — добавить. Возвращает индекс или -1 */
    for (int i = 0; i < HUB_MAX_CLIENTS; ++i) {
        if (h->clients[i].used) {
            if (h->clients[i].addr.sin_addr.s_addr == src->sin_addr.s_addr &&
                h->clients[i].addr.sin_port == src->sin_port) {
                h->clients[i].last_seen = time(NULL);
                return i;
            }
        }
    }
    /* добавить */
    for (int i = 0; i < HUB_MAX_CLIENTS; ++i) {
        if (!h->clients[i].used) {
            h->clients[i].used = 1;
            h->clients[i].addr = *src;
            h->clients[i].last_seen = time(NULL);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src->sin_addr, buf, sizeof(buf));
            fprintf(stderr, "[hub] new client %s:%u (slot %d)\n", buf, ntohs(src->sin_port), i);
            return i;
        }
    }
    return -1;
}

static void hub_prune(Hub *h) {
    time_t now = time(NULL);
    for (int i = 0; i < HUB_MAX_CLIENTS; ++i) {
        if (h->clients[i].used) {
            if (now - h->clients[i].last_seen > HUB_CLIENT_TIMEOUT_SEC) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &h->clients[i].addr.sin_addr, buf, sizeof(buf));
                fprintf(stderr, "[hub] remove client %s:%u (slot %d) due timeout\n", buf, ntohs(h->clients[i].addr.sin_port), i);
                h->clients[i].used = 0;
            }
        }
    }
}

static int hub_count(Hub *h) {
    int c = 0;
    for (int i = 0; i < HUB_MAX_CLIENTS; ++i) if (h->clients[i].used) c++;
    return c;
}

static void hub_forward(Hub *h, const uint8_t *buf, size_t len, const struct sockaddr_in *src) {
    /* пересылаем пакеты всем зарегистрированным клиентам, кроме src */
    for (int i = 0; i < HUB_MAX_CLIENTS; ++i) {
        if (!h->clients[i].used) continue;
        if (h->clients[i].addr.sin_addr.s_addr == src->sin_addr.s_addr &&
            h->clients[i].addr.sin_port == src->sin_port) continue; /* не посылаем обратно отправителю */
        sendto(h->sock, (const char*)buf, (int)len, 0,
               (struct sockaddr*)&h->clients[i].addr, sizeof(h->clients[i].addr));
    }
}

static THREAD_RET hub_thread(void *arg) {
    Hub *h = (Hub*)arg;
    uint8_t rbuf[AC_UDP_RECV_BUFSZ];
    while (atomic_load(&h->running)) {
        struct sockaddr_in src;
#ifdef _WIN32
        int slen = sizeof(src);
#else
        socklen_t slen = sizeof(src);
#endif
        int n = recvfrom(h->sock, (char*)rbuf, (int)sizeof(rbuf), 0,
                         (struct sockaddr*)&src, &slen);
        if (n <= 0) {
            msleep(5);
            hub_prune(h);
            continue;
        }
        /* Регистрация клиента (или обновление таймера) */
        int idx = hub_find_or_add(h, &src);
        if (idx < 0) continue; /* нет места */
        /* Пересылка всем остальным */
        hub_forward(h, rbuf, (size_t)n, &src);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int hub_main(uint16_t bind_port) {
    if (net_init_once() != 0) return -1;
    socket_t sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == (socket_t)SOCK_ERR) {
        fprintf(stderr, "hub: socket() failed\n");
        return -1;
    }
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(bind_port);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCK_ERR) {
        fprintf(stderr, "hub: bind() failed (port %u)\n", bind_port);
        CLOSESOCK(sock);
        return -1;
    }
    Hub h;
    hub_init(&h, sock);
    fprintf(stderr, "[hub] listening on *:%u\n", bind_port);

#ifdef _WIN32
    h.th = CreateThread(NULL, 0, hub_thread, &h, 0, NULL);
    if (!h.th) {
        CLOSESOCK(sock);
        return -1;
    }
#else
    if (pthread_create(&h.th, NULL, hub_thread, &h) != 0) {
        CLOSESOCK(sock);
        return -1;
    }
#endif

    fprintf(stderr, "[hub] running. Press Ctrl+C to stop.\n");
    while (atomic_load(&h.running)) {
#ifdef _WIN32
        if (GetAsyncKeyState(VK_CANCEL) || GetAsyncKeyState(VK_ESCAPE)) break;
#else
        /* Ctrl+C в POSIX */
        msleep(100);
#endif
    }
    atomic_store(&h.running, 0);
#ifdef _WIN32
    WaitForSingleObject(h.th, INFINITE);
    CloseHandle(h.th);
#else
    pthread_join(h.th, NULL);
#endif
    CLOSESOCK(sock);
    fprintf(stderr, "[hub] stopped.\n");
    return 0;
}

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
                "  %s call <remote_ip> <remote_port> <hexkey32> [local_bind_port]\n"
                "  %s listen <local_bind_port> <hexkey32>\n"
                "  %s hub <bind_port>\n",
                argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        if (sodium_init() < 0) return 1;
        uint8_t key[AES_GCM_KEY_LEN];
        randombytes_buf(key, sizeof(key));
        print_hex(key, sizeof(key));
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
        if (argc < 5) {
            fprintf(stderr, "Usage: %s call <remote_ip> <remote_port> <hexkey32> [local_bind_port]\n", argv[0]);
            return 1;
        }
        const char *ip = argv[2];
        uint16_t rport = (uint16_t)atoi(argv[3]);
        const char *hexkey = argv[4];
        uint16_t lport = (argc >= 6) ? (uint16_t)atoi(argv[5]) : 0;

        uint8_t key[AES_GCM_KEY_LEN];
        if (hex2bytes(hexkey, key, sizeof(key)) != 0) {
            fprintf(stderr, "Invalid key (must be 64 hex chars)\n");
            return 1;
        }

        AudioCall *call = NULL;
        if (audio_call_start(&call, ip, rport, lport, 1, key) != 0) {
            fprintf(stderr, "Failed to start call\n");
            return 1;
        }

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
        if (argc < 4) {
            fprintf(stderr, "Usage: %s listen <local_bind_port> <hexkey32>\n", argv[0]);
            return 1;
        }
        uint16_t lport = (uint16_t)atoi(argv[2]);
        const char *hexkey = argv[3];

        uint8_t key[AES_GCM_KEY_LEN];
        if (hex2bytes(hexkey, key, sizeof(key)) != 0) {
            fprintf(stderr, "Invalid key (must be 64 hex chars)\n");
            return 1;
        }

        AudioCall *call = NULL;
        if (audio_call_start(&call, NULL, 0, lport, 0, key) != 0) {
            fprintf(stderr, "Failed to start listener\n");
            return 1;
        }

        setup_signal();
        printf("Listening on *:%u (press Ctrl+C to stop)\n", lport);
        while (!atomic_load(&g_sigint)) {
            msleep(100);
        }
        audio_call_stop(call);
        printf("Listener stopped\n");
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}