/*
 * test_media_routing - кому ретранслятор рассылает медиа.
 *
 * У участника два соединения под одной меткой сессии: чат и звонок. Релей
 * исключал из рассылки только сокет отправителя, и медиа уходило во все
 * прочие соединения комнаты - в чаты, где его читают и выбрасывают, и в чат
 * самого отправителя, то есть его же поток возвращался к нему. На живом
 * звонке это была лишняя полоса видео вниз по Wi-Fi телефона: 211 МБ за
 * сеанс в сокет, который ничего не показывает.
 *
 * Здесь два участника, A и B, у каждого чат и звонок. Утверждается:
 *
 *   - медиа A доходит до звонка B - ровно один раз;
 *   - не доходит ни до одного чата и не возвращается к A;
 *   - и то же в обратную сторону;
 *   - текст чата по-прежнему доходит до чата другого участника.
 *
 * Кадр: [2 room_len][room][2 name_len][name][2 nonce_len][nonce][1 type]
 *       [4 clen][payload], все целые little-endian. Сервер поднимает обёртка
 * media_routing.sh.
 *
 * args: host port
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define T_TEXT   0
#define T_MEDIA 17
#define NONCE   12

static const char *ROOM = "r:media-routing-test";

static int failures = 0;

static void check(int cond, const char *what) {
    printf("%s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) failures++;
}

static int dial(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = v >> 24;
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int send_frame(int fd, const char *tag, uint8_t type, const char *payload) {
    size_t rl = strlen(ROOM), nl = strlen(tag), pl = strlen(payload);
    size_t len = 2 + rl + 2 + nl + 2 + NONCE + 1 + 4 + pl;
    uint8_t *f = calloc(1, len);
    if (!f) return -1;
    uint8_t *w = f;
    put16(w, (uint16_t)rl); w += 2; memcpy(w, ROOM, rl); w += rl;
    put16(w, (uint16_t)nl); w += 2; memcpy(w, tag, nl); w += nl;
    put16(w, NONCE); w += 2; w += NONCE;          /* нулевой нонс */
    *w++ = type;
    put32(w, (uint32_t)pl); w += 4; memcpy(w, payload, pl);
    ssize_t n = send(fd, f, len, 0);
    free(f);
    return n == (ssize_t)len ? 0 : -1;
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/*
 * Читать всё, что придёт за `ms` миллисекунд, и сосчитать кадры типа `type`
 * с полезной нагрузкой ровно `want`. want == NULL - просто вычерпать сокет.
 */
static int count_frames(int fd, uint8_t type, const char *want, int ms) {
    static uint8_t buf[1 << 20];
    size_t have = 0;
    long end = now_ms() + ms;
    for (;;) {
        long left = end - now_ms();
        if (left <= 0) break;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, (int)left) <= 0) break;
        ssize_t n = recv(fd, buf + have, sizeof buf - have, 0);
        if (n <= 0) break;
        have += (size_t)n;
        if (have == sizeof buf) break;
    }
    int count = 0;
    size_t off = 0;
    while (off + 2 <= have) {
        size_t o = off;
        uint16_t rl = get16(buf + o); o += 2 + rl;
        if (o + 2 > have) break;
        uint16_t nl = get16(buf + o); o += 2 + nl;
        if (o + 2 > have) break;
        uint16_t ncl = get16(buf + o); o += 2 + ncl;
        if (o + 1 + 4 > have) break;
        uint8_t t = buf[o]; o += 1;
        uint32_t cl = get32(buf + o); o += 4;
        if (o + cl > have) break;
        if (want && t == type && cl == strlen(want) && memcmp(buf + o, want, cl) == 0) {
            count++;
        }
        off = o + cl;
    }
    return count;
}

static void drain(int *fds, int n) {
    for (int i = 0; i < n; i++) count_frames(fds[i], 0, NULL, 150);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s host port\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);

    /* Порядок как в жизни: сперва чат, потом звонок под той же меткой.
     * Первый кадр соединения его и регистрирует: медиа - значит звонок. */
    int a_chat = dial(host, port);
    if (a_chat < 0 || send_frame(a_chat, "tagA", T_TEXT, "hello-a") != 0) {
        fprintf(stderr, "cannot reach the relay\n");
        return 1;
    }
    int b_chat = dial(host, port);
    int a_call = dial(host, port);
    int b_call = dial(host, port);
    if (b_chat < 0 || a_call < 0 || b_call < 0 ||
        send_frame(b_chat, "tagB", T_TEXT, "hello-b") != 0 ||
        send_frame(a_call, "tagA", T_MEDIA, "register-a") != 0 ||
        send_frame(b_call, "tagB", T_MEDIA, "register-b") != 0) {
        fprintf(stderr, "cannot set up four connections\n");
        return 1;
    }
    usleep(300 * 1000);
    int all[] = { a_chat, b_chat, a_call, b_call };
    drain(all, 4);

    /* A говорит в звонок. */
    if (send_frame(a_call, "tagA", T_MEDIA, "MEDIA-FROM-A") != 0) return 1;
    usleep(200 * 1000);
    check(count_frames(b_call, T_MEDIA, "MEDIA-FROM-A", 400) == 1,
          "media from A reaches B's call exactly once");
    check(count_frames(b_chat, T_MEDIA, "MEDIA-FROM-A", 200) == 0,
          "media from A does not reach B's chat");
    check(count_frames(a_chat, T_MEDIA, "MEDIA-FROM-A", 200) == 0,
          "media from A does not come back to A's own chat");
    check(count_frames(a_call, T_MEDIA, "MEDIA-FROM-A", 200) == 0,
          "media from A does not come back to A's call");

    /* И B в обратную сторону. */
    if (send_frame(b_call, "tagB", T_MEDIA, "MEDIA-FROM-B") != 0) return 1;
    usleep(200 * 1000);
    check(count_frames(a_call, T_MEDIA, "MEDIA-FROM-B", 400) == 1,
          "media from B reaches A's call exactly once");
    check(count_frames(a_chat, T_MEDIA, "MEDIA-FROM-B", 200) == 0,
          "media from B does not reach A's chat");
    check(count_frames(b_chat, T_MEDIA, "MEDIA-FROM-B", 200) == 0,
          "media from B does not come back to B's own chat");

    /* Чат при этом не задет: текст A доходит до чата B. */
    if (send_frame(a_chat, "tagA", T_TEXT, "TEXT-FROM-A") != 0) return 1;
    usleep(200 * 1000);
    check(count_frames(b_chat, T_TEXT, "TEXT-FROM-A", 400) == 1,
          "chat text from A still reaches B's chat");

    for (int i = 0; i < 4; i++) close(all[i]);
    printf("%s\n", failures ? "FAILED" : "PASS: media goes to calls only, never back to the sender");
    return failures ? 1 : 0;
}
