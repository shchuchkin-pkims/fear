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

/* net_init_once() теперь в audio_network.h */

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

    if (c->sock) {
        CLOSESOCK(c->sock);
        c->sock = 0;
    }

    pcmring_free(&c->out_ring);
    free(c);
}

int audio_call_start(AudioCall **out_call,
                     const char *remote_ip, uint16_t remote_port,
                     uint16_t bind_port,
                     int is_caller,
                     const uint8_t key[AES_GCM_KEY_LEN],
                     int input_device_id,
                     int output_device_id)
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
            fprintf(stderr, "Usage: %s call <remote_ip> <remote_port> [--key-file FILE] [local_bind_port] [input_dev] [output_dev]\n", argv[0]);
            return 1;
        }
        const char *ip = argv[2];
        uint16_t rport = (uint16_t)atoi(argv[3]);

        // Parse optional arguments
        const char *keyfile = NULL;
        const char *hexkey_arg = NULL;
        uint16_t lport = 0;
        int input_dev = -1;
        int output_dev = -1;
        int using_deprecated_key_arg = 0;

        int arg_idx = 4;
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "--key-file") == 0 && arg_idx + 1 < argc) {
                keyfile = argv[arg_idx + 1];
                arg_idx += 2;
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

        AudioCall *call = NULL;
        if (audio_call_start(&call, ip, rport, lport, 1, key, input_dev, output_dev) != 0) {
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
        if (argc < 3) {
            fprintf(stderr, "Usage: %s listen <local_bind_port> [--key-file FILE] [input_dev] [output_dev]\n", argv[0]);
            return 1;
        }
        uint16_t lport = (uint16_t)atoi(argv[2]);

        // Parse optional arguments
        const char *keyfile = NULL;
        const char *hexkey_arg = NULL;
        int input_dev = -1;
        int output_dev = -1;
        int using_deprecated_key_arg = 0;

        int arg_idx = 3;
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "--key-file") == 0 && arg_idx + 1 < argc) {
                keyfile = argv[arg_idx + 1];
                arg_idx += 2;
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

        AudioCall *call = NULL;
        if (audio_call_start(&call, NULL, 0, lport, 0, key, input_dev, output_dev) != 0) {
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