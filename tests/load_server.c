/**
 * @file load_server.c
 * @brief Put a crowd on the server and see what it does.
 *
 * Two questions, and the second is the one that matters:
 *
 *   How much does it carry - connections established, frames relayed,
 *   how long a round trip takes when the room is busy.
 *
 *   Do the caps hold. MAX_CONN_PER_IP and MAX_CLIENTS are what stop one
 *   source from eating every slot, and they were added as audit remediation.
 *   A limit nobody exercises is a limit nobody knows works.
 *
 * Source addresses matter here. The per-IP cap is 16, so a run from one
 * address cannot reach the global cap of 100 no matter how many sockets it
 * opens - which is the cap doing its job. To get past it the tool binds its
 * client sockets across 127.0.0.x, each of which the server sees as a
 * separate peer. That is a loopback-only trick and it is the point: it lets
 * one machine test both limits without pretending to be a botnet.
 *
 *     load_server 127.0.0.1 47777 --conns 80 --msgs 20 --spread 8
 *
 * Frames are well-formed but not encrypted: the server relays ciphertext
 * without reading it, so a load test does not need a key. The nonce is
 * non-zero on purpose - an all-zero nonce marks a service message and would
 * be routed somewhere else entirely.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_CONNS 512
#define ROOM "loadroom"
#define PAYLOAD_BYTES 64

static double now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void wr_u16le(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; }
static void wr_u32le(uint8_t *p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}

/** One frame, exactly as the server expects to route it. */
static size_t build_frame(uint8_t *out, size_t cap, const char *name,
                          uint8_t type, const uint8_t *payload, size_t plen) {
    size_t room_len = strlen(ROOM);
    size_t name_len = strlen(name);
    size_t nonce_len = 12;
    size_t need = 2 + room_len + 2 + name_len + 2 + nonce_len + 1 + 4 + plen;
    if (need > cap) return 0;

    uint8_t *w = out;
    wr_u16le(w, (uint16_t)room_len); w += 2;
    memcpy(w, ROOM, room_len); w += room_len;
    wr_u16le(w, (uint16_t)name_len); w += 2;
    memcpy(w, name, name_len); w += name_len;
    wr_u16le(w, (uint16_t)nonce_len); w += 2;
    /* Non-zero: an all-zero nonce is how a service message announces itself. */
    memset(w, 0x5A, nonce_len); w += nonce_len;
    *w++ = type;
    wr_u32le(w, (uint32_t)plen); w += 4;
    memcpy(w, payload, plen);
    return need;
}

static int connect_from(const char *host, int port, uint32_t source_index) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    if (source_index > 0) {
        /* 127.0.0.<n>: a distinct peer as far as the per-IP cap is concerned. */
        struct sockaddr_in src;
        memset(&src, 0, sizeof src);
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = htonl(0x7F000001u + source_index);
        if (bind(fd, (struct sockaddr *)&src, sizeof src) != 0) {
            close(fd);
            return -1;
        }
    }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 47777;
    int conns = 32, msgs = 10, spread = 4, expect = -1;

    for (int i = 3; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--conns"))  conns  = atoi(argv[i + 1]);
        if (!strcmp(argv[i], "--msgs"))   msgs   = atoi(argv[i + 1]);
        if (!strcmp(argv[i], "--spread")) spread = atoi(argv[i + 1]);
        /* Turns a measurement into an assertion, so the caps can be a
         * regression test rather than a number somebody has to read. */
        if (!strcmp(argv[i], "--expect"))  expect = atoi(argv[i + 1]);
    }
    if (conns > MAX_CONNS) conns = MAX_CONNS;
    if (spread < 1) spread = 1;

    printf("target %s:%d, %d connections over %d source address(es), %d messages each\n",
           host, port, conns, spread, msgs);

    int fds[MAX_CONNS];
    char names[MAX_CONNS][32];
    int established = 0, refused = 0;

    double t_connect = now_ms();
    for (int i = 0; i < conns; i++) {
        uint32_t src = (spread > 1) ? (uint32_t)(i % spread) : 0;
        fds[i] = connect_from(host, port, src);
        if (fds[i] < 0) { refused++; continue; }
        snprintf(names[i], sizeof names[i], "load%03d", i);

        /* Registration: the server learns room and name from the first frame. */
        uint8_t frame[512];
        uint8_t empty[1] = { ' ' };
        size_t flen = build_frame(frame, sizeof frame, names[i], 0, empty, 1);
        if (flen == 0 || send(fds[i], frame, flen, MSG_NOSIGNAL) != (ssize_t)flen) {
            close(fds[i]);
            fds[i] = -1;
            refused++;
            continue;
        }
        established++;
    }
    double connect_ms = now_ms() - t_connect;

    /* connect() succeeding proves nothing: the kernel completes the handshake
     * from the accept backlog, and a server over its cap closes the socket
     * afterwards. The client only finds out by reading EOF. Counting sockets
     * as established here reported 40 of 40 while the server was refusing 24
     * of them - and then every round waited out its full deadline for
     * replies that were never coming. */
    usleep(300 * 1000);
    for (int i = 0; i < conns; i++) {
        if (fds[i] < 0) continue;
        struct pollfd p = { fds[i], POLLIN, 0 };
        if (poll(&p, 1, 0) <= 0) continue;

        int turned_away = (p.revents & (POLLHUP | POLLERR)) != 0;
        if (!turned_away && (p.revents & POLLIN)) {
            uint8_t probe[64];
            ssize_t n = recv(fds[i], probe, sizeof probe, MSG_DONTWAIT | MSG_PEEK);
            /* Zero is an orderly close. A reset is the same answer said less
             * politely, and it is the usual one here: the server closes with
             * our registration frame still unread, which makes it an RST. */
            if (n == 0 || (n < 0 && (errno == ECONNRESET || errno == EPIPE))) {
                turned_away = 1;
            }
        }

        if (turned_away) {
            close(fds[i]);
            fds[i] = -1;
            established--;
            refused++;
        }
    }

    printf("established %d, refused %d, in %.0f ms\n", established, refused, connect_ms);

    if (expect >= 0 && established != expect) {
        fprintf(stderr, "load_server: expected %d established, got %d\n",
                expect, established);
        for (int i = 0; i < conns; i++) if (fds[i] >= 0) close(fds[i]);
        return 2;
    }
    if (established == 0) {
        fprintf(stderr, "nothing connected - is the server up?\n");
        return 1;
    }

    /* Let registrations settle before measuring anything. */
    usleep(200 * 1000);
    for (int i = 0; i < conns; i++) {
        if (fds[i] < 0) continue;
        uint8_t drain[65536];
        struct pollfd p = { fds[i], POLLIN, 0 };
        while (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) {
            if (recv(fds[i], drain, sizeof drain, MSG_DONTWAIT) <= 0) break;
        }
    }

    /* Every sender's frame goes to every other member, so the traffic the
     * server moves grows with the square of the room. That is the number
     * worth reporting, not the count of sends. */
    uint8_t payload[PAYLOAD_BYTES];
    memset(payload, 0x42, sizeof payload);

    double *rtt = calloc((size_t)msgs, sizeof *rtt);
    long long sent = 0, received = 0;
    double t0 = now_ms();

    for (int m = 0; m < msgs; m++) {
        double t_send = now_ms();
        for (int i = 0; i < conns; i++) {
            if (fds[i] < 0) continue;
            uint8_t frame[512];
            size_t flen = build_frame(frame, sizeof frame, names[i], 0,
                                      payload, sizeof payload);
            if (send(fds[i], frame, flen, MSG_NOSIGNAL) == (ssize_t)flen) sent++;
        }

        /* Drain what came back, and time the first arrival of this round. */
        double first_in = 0.0;
        double deadline = now_ms() + 2000.0;
        long long want = (long long)established * (established - 1);
        long long got = 0;

        while (now_ms() < deadline && got < want) {
            struct pollfd p[MAX_CONNS];
            int np = 0;
            int idx[MAX_CONNS];
            for (int i = 0; i < conns; i++) {
                if (fds[i] < 0) continue;
                p[np].fd = fds[i]; p[np].events = POLLIN; p[np].revents = 0;
                idx[np] = i; np++;
            }
            if (np == 0) break;
            if (poll(p, np, 50) <= 0) continue;

            for (int k = 0; k < np; k++) {
                if (!(p[k].revents & POLLIN)) continue;
                uint8_t buf[65536];
                ssize_t n = recv(fds[idx[k]], buf, sizeof buf, MSG_DONTWAIT);
                if (n <= 0) continue;
                if (first_in == 0.0) first_in = now_ms();
                /* Bytes, not frames: several arrive coalesced and counting
                 * frames would mean parsing, which is not what is under test. */
                got += n / 96;
                received += n / 96;
            }
        }
        rtt[m] = (first_in > 0.0) ? (first_in - t_send) : -1.0;
    }

    double elapsed = now_ms() - t0;

    qsort(rtt, (size_t)msgs, sizeof *rtt, cmp_double);
    double p50 = rtt[msgs / 2];
    double p99 = rtt[(msgs * 99) / 100];

    printf("sent %lld frames, saw about %lld relayed, in %.0f ms\n",
           sent, received, elapsed);
    printf("relay rate about %.0f frames/s\n", received * 1000.0 / elapsed);
    printf("first-arrival latency p50 %.1f ms, p99 %.1f ms\n", p50, p99);

    for (int i = 0; i < conns; i++) if (fds[i] >= 0) close(fds[i]);
    free(rtt);
    return 0;
}
