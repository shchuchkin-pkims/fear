#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>  // Добавлено
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/select.h>
#include <errno.h>   // Добавлено для errno
#endif

static sock_t dial_tcp(const char *host, uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int e = getaddrinfo(host, portstr, &hints, &res);
    if (e != 0) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e)); exit(1); }
    sock_t s = -1;
    struct addrinfo *ai;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) break;
        close_socket(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) die("connect");
    return s;
}

int send_ciphertext(sock_t s, const char *room, const char *name, const uint8_t *key,
                   const uint8_t *plaintext, size_t plen) {
    uint16_t room_len = (uint16_t)strlen(room);
    uint16_t name_len = (uint16_t)strlen(name);
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) return -1;
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

    size_t cmax = plen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *cipher = (uint8_t*)malloc(cmax);
    if (!cipher) { free(ad); return -1; }
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, &clen, plaintext, plen, ad, ad_len, NULL, nonce, key);

    size_t flen = 2 + room_len + 2 + name_len + 2 + sizeof(nonce) + 4 + (size_t)clen;
    uint8_t *frame = (uint8_t*)malloc(flen);
    if (!frame) { free(ad); free(cipher); return -1; }
    w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len); w += name_len;
    wr_u16(w, (uint16_t)sizeof(nonce)); w += 2; memcpy(w, nonce, sizeof(nonce)); w += sizeof(nonce);
    wr_u32(w, (uint32_t)clen); w += 4; memcpy(w, cipher, clen);

    int rc = send_all(s, frame, flen);
    free(ad);
    free(cipher);
    free(frame);
    return rc;
}

int recv_and_decrypt(sock_t s, const char *room, const uint8_t *key, const char *myname) {
    uint8_t hdr2[2];
    if (recv_all(s, hdr2, 2) < 0) return -1;
    uint16_t room_len = rd_u16(hdr2);
    if (room_len > MAX_ROOM) return -1;
    char *room_in = (char*)malloc(room_len + 1);
    if (!room_in) return -1;
    if (recv_all(s, room_in, room_len) < 0) { free(room_in); return -1; }
    room_in[room_len] = '\0';

    uint8_t nlenbuf[2];
    if (recv_all(s, nlenbuf, 2) < 0) { free(room_in); return -1; }
    uint16_t name_len = rd_u16(nlenbuf);
    if (name_len > MAX_NAME) { free(room_in); return -1; }
    char *name = (char*)malloc(name_len + 1);
    if (!name) { free(room_in); return -1; }
    if (recv_all(s, name, name_len) < 0) { free(room_in); free(name); return -1; }
    name[name_len] = '\0';

    uint8_t npbuf[2];
    if (recv_all(s, npbuf, 2) < 0) { free(room_in); free(name); return -1; }
    uint16_t nonce_len = rd_u16(npbuf);
    if (nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) { free(room_in); free(name); return -1; }
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    if (recv_all(s, nonce, nonce_len) < 0) { free(room_in); free(name); return -1; }

    uint8_t clenbuf[4];
    if (recv_all(s, clenbuf, 4) < 0) { free(room_in); free(name); return -1; }
    uint32_t clen = rd_u32(clenbuf);
    if (clen > MAX_FRAME) { free(room_in); free(name); return -1; }
    uint8_t *cipher = (uint8_t*)malloc(clen);
    if (!cipher) { free(room_in); free(name); return -1; }
    if (recv_all(s, cipher, clen) < 0) { free(room_in); free(name); free(cipher); return -1; }

    size_t ad_len = room_len + name_len + 2 + 2;
    uint8_t *ad = (uint8_t*)malloc(ad_len);
    if (!ad) { free(room_in); free(name); free(cipher); return -1; }
    uint8_t *w = ad;
    wr_u16(w, room_len); w += 2; memcpy(w, room_in, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, name, name_len);

    int same_room = (strcmp(room, room_in) == 0);
    uint8_t *plain = (uint8_t*)malloc(clen);
    if (!plain) { free(room_in); free(name); free(cipher); free(ad); return -1; }
    unsigned long long plen = 0;
    int ok = -1;
    if (same_room) {
        ok = crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &plen, NULL, cipher, clen, ad, ad_len, nonce, key);
    }

    if (!same_room || ok != 0 || strcmp(name, myname) == 0) {
        free(room_in); free(name); free(cipher); free(ad); free(plain);
        return 0;
    }

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char tbuf[32];
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm);
    printf("[%s] %s: %.*s\n", tbuf, name, (int)plen, (char*)plain);
    fflush(stdout);

    free(room_in); free(name); free(cipher); free(ad); free(plain);
    return 1;
}

void print_local_message(const char *name, const char *msg) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char tbuf[9];
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", tm_info);
    printf("[%s] %s: %s\n", tbuf, name, msg);
    fflush(stdout);
}

#ifdef _WIN32
typedef struct {
    SOCKET s;
    const char *room;
    const char *name;
    const uint8_t *key;
} input_ctx_t;

DWORD WINAPI input_thread(LPVOID param) {
    input_ctx_t *ctx = (input_ctx_t*)param;
    char line[4096];
    for (;;) {
        if (!fgets(line, sizeof line, stdin)) break;
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) continue;
        if (send_ciphertext(ctx->s, ctx->room, ctx->name, ctx->key, (uint8_t*)line, len) < 0) {
            printf("send failed (connection lost?)\n");
            break;
        }
        print_local_message(ctx->name, line);
    }
    return 0;
}
#endif

void run_client(const char *host, uint16_t port, const char *room, const char *name, const uint8_t key[32]) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); exit(1); }
    sock_t s = dial_tcp(host, port);
    printf("[client] connected to %s:%u, room=\"%s\"\n", host, port, room);
    printf("Type messages and press Enter. Ctrl+C to exit.\n");

#ifdef _WIN32
    input_ctx_t ctx;
    ctx.s = s;
    ctx.room = room;
    ctx.name = name;
    ctx.key = key;
    HANDLE hThread = CreateThread(NULL, 0, input_thread, &ctx, 0, NULL);
    if (!hThread) { fprintf(stderr, "thread create failed\n"); exit(1); }
    for (;;) {
        int rc = recv_and_decrypt(ctx.s, ctx.room, ctx.key, ctx.name);
        if (rc < 0) {
            printf("[client] disconnected\n");
            break;
        }
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
#else
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = (s > STDIN_FILENO ? s : STDIN_FILENO) + 1;
        int r = select(maxfd, &rfds, NULL, NULL, NULL);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (FD_ISSET(s, &rfds)) {
            int rc = recv_and_decrypt(s, room, key, name);
            if (rc < 0) { printf("[client] disconnected\n"); break; }
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            char *line = NULL;
            size_t cap = 0;
            ssize_t n = getline(&line, &cap, stdin);
            if (n <= 0) { free(line); break; }
            size_t len = (size_t)n;
            if (len && line[len - 1] == '\n') line[--len] = '\0';
            if (len == 0) { free(line); continue; }
            if (send_ciphertext(s, room, name, key, (uint8_t*)line, len) < 0) {
                printf("send failed\n");
                free(line);
                break;
            }
            print_local_message(name, line);
            free(line);
        }
    }
#endif
    close_socket(s);
}