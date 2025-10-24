/**
 * @file server.c
 * @brief F.E.A.R. message relay server implementation
 *
 * This server acts as a relay for encrypted messages between clients.
 * It NEVER has access to message plaintext - all messages are end-to-end
 * encrypted by clients using room keys. The server only sees metadata:
 * - Room names
 * - User names
 * - Message sizes
 *
 * Server responsibilities:
 * - Accept client connections
 * - Route messages to correct room participants
 * - Enforce unique names per room
 * - Broadcast user list changes
 * - Handle client disconnections
 */

#include "server.h"
#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <sodium.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/select.h>
#include <errno.h>
#endif

/**
 * @brief Connected client information
 *
 * Stores per-client state for the server. Room and name are extracted
 * from the first message and remain fixed for the connection.
 */
typedef struct {
    sock_t fd;              /**< Socket descriptor for this client */
    char room[MAX_ROOM];    /**< Room name (empty until first message) */
    char name[MAX_NAME];    /**< User name (empty until first message) */
} client_t;

/**
 * @brief Read a complete protocol frame from client socket
 *
 * Reads and reassembles a complete message frame in the protocol format:
 * [2 room_len][room][2 name_len][name][2 nonce_len][nonce][1 type][4 clen][cipher]
 *
 * The server doesn't decrypt messages - it just forwards them to other
 * clients in the same room.
 *
 * @param fd Client socket descriptor
 * @param out Receives pointer to allocated frame buffer
 * @param outlen Receives total frame length
 * @return 0 on success, -1 on error or disconnect
 *
 * @note Caller must free(*out) after use
 * @note Returns -1 if frame is malformed or exceeds limits
 */
static int read_frame(sock_t fd, uint8_t **out, size_t *outlen) {
    uint8_t hdr[2];
    if (recv_all(fd, hdr, 2) < 0) {
        return -1;
    }

    uint16_t room_len = rd_u16(hdr);
    if (room_len > MAX_ROOM) {
        return -1;
    }

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

/**
 * @brief Broadcast a message to all clients in the same room
 *
 * Forwards the message frame to all connected clients who are in the
 * specified room, except the sender.
 *
 * @param clients Array of connected clients
 * @param nclients Pointer to client count (may be decremented if client disconnects)
 * @param room Target room name
 * @param frame Complete message frame to broadcast
 * @param flen Frame length in bytes
 * @param from Socket of sender (to avoid echoing message back)
 *
 * @note Automatically removes clients if send fails
 */
static void broadcast(client_t *clients, int *nclients, const char *room,
                     const uint8_t *frame, size_t flen, sock_t from) {
    /* Extract frame fields to validate structure */
    if (flen < 2) return;
    uint16_t room_len = rd_u16(frame);
    if (2 + (size_t)room_len + 2 > flen) return;
    uint16_t name_len = rd_u16(frame + 2 + room_len);
    if (2 + (size_t)room_len + 2 + (size_t)name_len + 2 > flen) return;

    /* Frame is valid, broadcast to room participants */
    (void)room; /* Suppress unused parameter warning */

    for (int i = 0; i < *nclients; i++) {
        if (clients[i].fd == from) {
            continue; /* Don't echo back to sender */
        }

        /* Skip clients that haven't registered yet */
        if (clients[i].room[0] == '\0') {
            continue;
        }

        /* Only send to clients in same room */
        if (strcmp(clients[i].room, room) != 0) {
            continue;
        }

        /* Send frame to client; remove if send fails */
        if (send_all(clients[i].fd, frame, flen) < 0) {
            close_socket(clients[i].fd);
            clients[i] = clients[*nclients - 1];
            (*nclients)--;
            i--;
        }
    }
}

/**
 * @brief Send updated room participant list to all clients in room
 *
 * Broadcasts MSG_TYPE_USER_LIST message containing names of all users
 * currently in the specified room. Called when user joins or leaves.
 *
 * @param clients Array of all connected clients
 * @param nclients Total number of connected clients
 * @param room Room name to send list for
 *
 * @note Uses zero nonce (service message, not encrypted)
 * @note Sent from "server" name to distinguish from user messages
 */
static void send_user_list(client_t *clients, int nclients, const char *room) {
    /* Build list of participant names */
    char user_list[MAX_FRAME];
    size_t offset = 0;
    int count = 0;

    for (int i = 0; i < nclients; i++) {
        if (clients[i].room[0] != '\0' && strcmp(clients[i].room, room) == 0) {
            size_t name_len = strlen(clients[i].name);
            if (offset + 2 + name_len < sizeof(user_list) - 100) {
                wr_u16((uint8_t*)(user_list + offset), (uint16_t)name_len);
                offset += 2;
                memcpy(user_list + offset, clients[i].name, name_len);
                offset += name_len;
                count++;
            }
        }
    }

    if (count == 0) return;

    // Формируем сообщение MSG_TYPE_USER_LIST
    // Формат payload: [2 count][для каждого: 2 name_len, name]
    uint8_t payload[MAX_FRAME];
    wr_u16(payload, (uint16_t)count);
    memcpy(payload + 2, user_list, offset);
    size_t payload_len = 2 + offset;

    // Отправляем всем клиентам комнаты
    for (int i = 0; i < nclients; i++) {
        if (clients[i].room[0] == '\0' || strcmp(clients[i].room, room) != 0) continue;

        // Формируем frame с MSG_TYPE_USER_LIST
        uint16_t room_len = (uint16_t)strlen(room);
        uint16_t name_len = (uint16_t)strlen("server"); // от имени сервера
        uint8_t nonce[CRYPTO_NPUBBYTES];
        memset(nonce, 0, sizeof(nonce)); // для служебных сообщений nonce = 0

        size_t frame_len = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + payload_len;
        uint8_t *frame = (uint8_t*)malloc(frame_len);
        if (!frame) continue;

        uint8_t *w = frame;
        wr_u16(w, room_len); w += 2;
        memcpy(w, room, room_len); w += room_len;
        wr_u16(w, name_len); w += 2;
        memcpy(w, "server", name_len); w += name_len;
        wr_u16(w, CRYPTO_NPUBBYTES); w += 2;
        memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
        *w++ = (uint8_t)MSG_TYPE_USER_LIST;
        wr_u32(w, (uint32_t)payload_len); w += 4;
        memcpy(w, payload, payload_len);

        send_all(clients[i].fd, frame, frame_len);
        free(frame);
    }
}


/**
 * @brief Main server loop - accept connections and relay messages
 *
 * Runs an event loop using select() to handle multiple clients concurrently:
 * 1. Accept new client connections
 * 2. Read messages from connected clients
 * 3. Broadcast messages to appropriate rooms
 * 4. Handle disconnections and errors
 *
 * The server maintains zero knowledge of message content - it only sees:
 * - Room names (metadata)
 * - User names (metadata)
 * - Encrypted ciphertext (cannot decrypt without room key)
 *
 * @param port TCP port to listen on (e.g., 8888)
 *
 * @note Runs indefinitely until interrupted (Ctrl+C)
 * @note Maximum MAX_CLIENTS (100) simultaneous connections
 */
void run_server(uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    // Set console code page to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#else
    // Set locale to UTF-8 for Linux/Android
    setlocale(LC_ALL, "");
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

                // Сохраняем комнату до удаления клиента
                char dropped_room[MAX_ROOM];
                if (clients[i].room[0] != '\0') {
                    strncpy(dropped_room, clients[i].room, MAX_ROOM - 1);
                    dropped_room[MAX_ROOM - 1] = '\0';
                } else {
                    dropped_room[0] = '\0';
                }

                close_socket(clients[i].fd);
                clients[i] = clients[nclients - 1];
                nclients--;
                i--;

                // Обновляем список участников для комнаты
                if (dropped_room[0] != '\0') {
                    send_user_list(clients, nclients, dropped_room);
                }

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
                // Проверяем уникальность имени в той же комнате
                int name_exists = 0;
                for (int j = 0; j < nclients; j++) {
                    if (i == j) continue; // Пропускаем себя
                    if (clients[j].name[0] != '\0' && clients[j].room[0] != '\0') {
                        // Сравниваем имена и комнаты
                        if (strncmp(clients[j].room, room, room_len) == 0 &&
                            clients[j].room[room_len] == '\0' &&
                            strncmp(clients[j].name, name, name_len) == 0 &&
                            clients[j].name[name_len] == '\0') {
                            name_exists = 1;
                            break;
                        }
                    }
                }

                if (name_exists) {
                    // Имя уже занято - отключаем клиента
                    printf("[server] client rejected: name '%.*s' already exists in room '%.*s'\n",
                           (int)name_len, name, (int)room_len, room);
                    close_socket(clients[i].fd);
                    clients[i] = clients[nclients - 1];
                    nclients--;
                    i--;
                    free(frame);
                    continue;
                }

                size_t nl = name_len < MAX_NAME - 1 ? name_len : MAX_NAME - 1;
                memcpy(clients[i].name, name, nl);
                clients[i].name[nl] = '\0';
                printf("[server] client registered: name='%s', room='%s'\n",
                       clients[i].name, clients[i].room);

                // Отправляем обновленный список участников всем в комнате
                send_user_list(clients, nclients, clients[i].room);
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