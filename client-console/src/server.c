#include "server.h"
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

typedef struct {
    sock_t fd;
    char room[MAX_ROOM];
    char name[MAX_NAME];
} client_t;

static int server_listen(uint16_t port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket");
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(s, 16) < 0) die("listen");
    return s;
}

static int read_frame(sock_t fd, uint8_t **out, size_t *outlen) {
    uint8_t hdr[2];
    if (recv_all(fd, hdr, 2) < 0) return -1;
    uint16_t room_len = rd_u16(hdr);
    if (room_len > MAX_ROOM) return -1;

    // временный буфер для header-полей (room + name + nonce)
    size_t bufsize = 2 + room_len + 2 + MAX_NAME + 2 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    uint8_t *buf = (uint8_t*)malloc(bufsize);
    if (!buf) return -1;
    memcpy(buf, hdr, 2);

    // read room + name_len
    if (recv_all(fd, buf + 2, room_len + 2) < 0) { free(buf); return -1; }
    uint16_t name_len = rd_u16(buf + 2 + room_len);
    if (name_len > MAX_NAME) { free(buf); return -1; }

    // read name
    if (recv_all(fd, buf + 2 + room_len + 2, name_len) < 0) { free(buf); return -1; }

    // read nonce_len (2 bytes)
    uint8_t nlbuf[2];
    if (recv_all(fd, nlbuf, 2) < 0) { free(buf); return -1; }
    uint16_t nonce_len = rd_u16(nlbuf);
    if (nonce_len != CRYPTO_NPUBBYTES) { free(buf); return -1; }

    // read nonce
    if (recv_all(fd, buf + 2 + room_len + 2 + name_len, nonce_len) < 0) { free(buf); return -1; }

    // read type (1 byte)
    uint8_t type_buf[1];
    if (recv_all(fd, type_buf, 1) < 0) { free(buf); return -1; }
    message_type_t msg_type = (message_type_t)type_buf[0];

    // read clen (4 bytes)
    uint8_t clenbuf[4];
    if (recv_all(fd, clenbuf, 4) < 0) { free(buf); return -1; }
    uint32_t clen = rd_u32(clenbuf);
    if (clen > MAX_FRAME) { free(buf); return -1; }

    // read cipher
    uint8_t *cipher = (uint8_t*)malloc(clen);
    if (!cipher) { free(buf); return -1; }
    if (recv_all(fd, cipher, clen) < 0) { free(buf); free(cipher); return -1; }

    // Собираем frame в унифицированном формате:
    // [2 room_len][room][2 name_len][name][2 nonce_len][nonce][1 type][4 clen][clen cipher]
    size_t total = 2 + room_len + 2 + name_len + 2 + nonce_len + 1 + 4 + clen;
    uint8_t *frame = (uint8_t*)malloc(total);
    if (!frame) { free(buf); free(cipher); return -1; }
    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2; memcpy(w, buf + 2, room_len); w += room_len;
    wr_u16(w, name_len); w += 2; memcpy(w, buf + 2 + room_len + 2, name_len); w += name_len;
    wr_u16(w, nonce_len); w += 2; memcpy(w, buf + 2 + room_len + 2 + name_len, nonce_len); w += nonce_len;
    *w++ = (uint8_t)msg_type;
    wr_u32(w, clen); w += 4;
    memcpy(w, cipher, clen);

    *out = frame;
    *outlen = total;
    free(buf);
    free(cipher);
    return 0;
}

static void broadcast(client_t *clients, int *nclients, const char *room, 
                     const uint8_t *frame, size_t flen, sock_t from) {
    // извлекаем room/name/nonce, чтобы найти offset для type
    if (flen < 2) return;
    uint16_t room_len = rd_u16(frame);
    if (2 + room_len + 2 > flen) return;
    uint16_t name_len = rd_u16(frame + 2 + room_len);
    if (2 + room_len + 2 + name_len + 2 > flen) return;
    uint16_t nonce_len = rd_u16(frame + 2 + room_len + 2 + name_len);
    size_t type_offset = 2 + room_len + 2 + name_len + 2 + nonce_len;
    if (type_offset + 1 > flen) return;
    message_type_t msg_type = (message_type_t)frame[type_offset];

    for (int i = 0; i < *nclients; i++) {
        if (clients[i].fd == from) continue;
        if (strcmp(clients[i].room, room) != 0) continue;

        // Можно при необходимости добавить логику фильтрации по типу
        if (send_all(clients[i].fd, frame, flen) < 0) {
            close_socket(clients[i].fd);
            clients[i] = clients[*nclients - 1];
            (*nclients)--;
            i--;
        }
    }
}


void run_server(uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    sock_t listener = server_listen(port);
    printf("[server] listening on 0.0.0.0:%u\n", port);
    client_t clients[MAX_CLIENTS];
    int nclients = 0;
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        sock_t maxfd = listener;
        for (int i = 0; i < nclients; i++) {
            FD_SET(clients[i].fd, &rfds);
            if (clients[i].fd > maxfd) maxfd = clients[i].fd;
        }
        int r = select((int)(maxfd + 1), &rfds, NULL, NULL, NULL);
        if (r < 0) { perror("select"); break; }
        if (FD_ISSET(listener, &rfds)) {
            struct sockaddr_in cli;
            socklen_t cl = sizeof(cli);
            sock_t c = accept(listener, (struct sockaddr*)&cli, &cl);
            if (c >= 0) {
                if (nclients < MAX_CLIENTS) {
                    clients[nclients].fd = c;
                    clients[nclients].room[0] = '\0';
                    clients[nclients].name[0] = '\0';
                    nclients++;
                    printf("[server] new connection (%d total)\n", nclients);
                } else {
                    close_socket(c);
                }
            }
        }
        for (int i = 0; i < nclients; i++) {
            if (!FD_ISSET(clients[i].fd, &rfds)) continue;
            uint8_t *frame = NULL;
            size_t flen = 0;
            if (read_frame(clients[i].fd, &frame, &flen) < 0) {
                printf("[server] client dropped\n");
                close_socket(clients[i].fd);
                clients[i] = clients[nclients - 1];
                nclients--;
                i--;
                continue;
            }
            uint16_t room_len = rd_u16(frame);
            const char *room = (const char*)(frame + 2);
            uint16_t name_len = rd_u16(frame + 2 + room_len);
            const char *name = (const char*)(frame + 2 + room_len + 2);
            if (clients[i].room[0] == '\0') {
                size_t rl = room_len < MAX_ROOM - 1 ? room_len : MAX_ROOM - 1;
                memcpy(clients[i].room, room, rl);
                clients[i].room[rl] = '\0';
            }
            if (clients[i].name[0] == '\0') {
                size_t nl = name_len < MAX_NAME - 1 ? name_len : MAX_NAME - 1;
                memcpy(clients[i].name, name, nl);
                clients[i].name[nl] = '\0';
            }
            broadcast(clients, &nclients, clients[i].room, frame, flen, clients[i].fd);
            free(frame);
        }
    }
    close_socket(listener);
#ifdef _WIN32
    WSACleanup();
#endif
}