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
#include "server_db.h"
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
#include <netinet/tcp.h>
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
    struct sockaddr_in udp_addr; /**< UDP address for relay */
    int udp_registered;     /**< Whether UDP relay address is set */
    int is_media_relay;     /**< Whether this is a media relay connection (allows duplicate name) */
    time_t last_seen;       /**< Wall-clock time of the last frame received from this client.
                                  Updated on accept and on every successful read_frame. The
                                  idle scan in the main loop closes connections with
                                  now - last_seen > IDLE_TIMEOUT_SEC. */
} client_t;

/**
 * How long a client may be silent before the server kicks it.
 * Clients send MSG_TYPE_PING at most every PING_INTERVAL_SEC (60s on both
 * Android and CLI), so 240s = four missed pings comfortably covers a brief
 * packet loss while still releasing the slot quickly after a real crash.
 */
#define IDLE_TIMEOUT_SEC 240

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
        if (clients[i].room[0] != '\0' && strcmp(clients[i].room, room) == 0
            && !clients[i].is_media_relay) {
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

    // Отправляем всем клиентам комнаты (skip media relay connections)
    for (int i = 0; i < nclients; i++) {
        if (clients[i].room[0] == '\0' || strcmp(clients[i].room, room) != 0
            || clients[i].is_media_relay) continue;

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
 * Build and send a HANDLE_RESULT frame back to the requesting client.
 *
 * Frame mirrors the wire format used everywhere else (room/name/zero-nonce/
 * type/clen/cipher); the cipher field carries the response payload directly
 * since handle commands are public service messages.
 *
 * Payload layout: [status(1)][reason_len(1)][reason][optional pk(0 or 32)]
 */
static void send_handle_result(sock_t fd, const char *room, uint16_t room_len,
                               uint8_t status, const char *reason,
                               const uint8_t *pk_or_null) {
    uint8_t  payload[256];
    size_t   payload_len = 0;
    payload[payload_len++] = status;

    uint8_t reason_len = reason ? (uint8_t)strlen(reason) : 0;
    if (reason_len > 200) reason_len = 200;
    payload[payload_len++] = reason_len;
    if (reason_len) {
        memcpy(payload + payload_len, reason, reason_len);
        payload_len += reason_len;
    }
    if (pk_or_null) {
        memcpy(payload + payload_len, pk_or_null, 32);
        payload_len += 32;
    }

    static const char *kSrvName = "server";
    uint16_t name_len = (uint16_t)strlen(kSrvName);
    uint8_t  nonce[CRYPTO_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));

    size_t frame_len = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + payload_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) return;

    uint8_t *w = frame;
    wr_u16(w, room_len);            w += 2;
    memcpy(w, room, room_len);      w += room_len;
    wr_u16(w, name_len);            w += 2;
    memcpy(w, kSrvName, name_len);  w += name_len;
    wr_u16(w, CRYPTO_NPUBBYTES);    w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)MSG_TYPE_HANDLE_RESULT;
    wr_u32(w, (uint32_t)payload_len); w += 4;
    memcpy(w, payload, payload_len);

    send_all(fd, frame, frame_len);
    free(frame);
}

/**
 * Inspect a freshly-read frame for handle-registry commands.
 * If the frame's type is REGISTER_HANDLE / LOOKUP_HANDLE, process it
 * locally (talks to server_db) and send a HANDLE_RESULT back.
 *
 * Returns 1 if the frame was a handle command (caller should NOT broadcast),
 *         0 if it's a regular text/file/etc frame to be broadcast as usual.
 */
static int try_handle_command(sock_t fd, const uint8_t *frame, size_t flen) {
    if (flen < 2) return 0;
    uint16_t room_len = rd_u16(frame);
    if (flen < (size_t)2 + room_len + 2) return 0;
    uint16_t name_len = rd_u16(frame + 2 + room_len);
    size_t off = 2 + room_len + 2 + name_len;
    if (flen < off + 2) return 0;
    uint16_t nonce_len = rd_u16(frame + off);
    off += 2 + nonce_len;
    if (flen < off + 1 + 4) return 0;
    uint8_t  type = frame[off];
    uint32_t clen = rd_u32(frame + off + 1);
    if (flen < off + 5 + clen) return 0;
    const uint8_t *cipher = frame + off + 5;
    const char    *room   = (const char *)(frame + 2);

    if (type == MSG_TYPE_REGISTER_HANDLE) {
        /* payload: [pk(32)][sig(64)][handle_len(1)][handle UTF-8] */
        if (clen < 32 + 64 + 1) {
            send_handle_result(fd, room, room_len, 2, "payload too short", NULL);
            return 1;
        }
        const uint8_t *pk        = cipher;
        const uint8_t *sig       = cipher + 32;
        uint8_t        handle_len = cipher[32 + 64];
        if (clen < (uint32_t)32 + 64 + 1 + handle_len) {
            send_handle_result(fd, room, room_len, 2, "truncated handle", NULL);
            return 1;
        }
        char handle[64];
        if (handle_len >= sizeof(handle)) handle_len = sizeof(handle) - 1;
        memcpy(handle, cipher + 32 + 64 + 1, handle_len);
        handle[handle_len] = '\0';

        /* Verify the Ed25519 sig over the handle bytes — proves the requester
         * actually owns identity_pk. */
        if (crypto_sign_verify_detached(sig, (const uint8_t *)handle,
                                        handle_len, pk) != 0) {
            send_handle_result(fd, room, room_len, 2, "bad signature", NULL);
            return 1;
        }

        handle_register_result_t rc = server_db_register_handle(handle, pk);
        switch (rc) {
            case HANDLE_REGISTER_OK:
                send_handle_result(fd, room, room_len, 0, "ok", pk);
                printf("[server] handle '%s' registered\n", handle);
                break;
            case HANDLE_REGISTER_CONFLICT:
                send_handle_result(fd, room, room_len, 1, "handle taken", NULL);
                break;
            case HANDLE_REGISTER_INVALID:
                send_handle_result(fd, room, room_len, 2, "invalid handle", NULL);
                break;
            default:
                send_handle_result(fd, room, room_len, 3, "server error", NULL);
                break;
        }
        return 1;
    }

    if (type == MSG_TYPE_LOOKUP_HANDLE) {
        if (clen < 1) {
            send_handle_result(fd, room, room_len, 2, "missing handle", NULL);
            return 1;
        }
        uint8_t handle_len = cipher[0];
        if (clen < (uint32_t)1 + handle_len) {
            send_handle_result(fd, room, room_len, 2, "truncated handle", NULL);
            return 1;
        }
        char handle[64];
        if (handle_len >= sizeof(handle)) handle_len = sizeof(handle) - 1;
        memcpy(handle, cipher + 1, handle_len);
        handle[handle_len] = '\0';

        uint8_t pk[32];
        int rc = server_db_lookup_handle(handle, pk);
        if (rc == 0)      send_handle_result(fd, room, room_len, 0, "ok", pk);
        else if (rc == 1) send_handle_result(fd, room, room_len, 1, "not found", NULL);
        else              send_handle_result(fd, room, room_len, 3, "server error", NULL);
        return 1;
    }

    if (type == MSG_TYPE_LOOKUP_HANDLE_BY_PK) {
        /* Reverse lookup — given identity_pk, return registered handle.
         * Used by clients after identity import to detect a pre-existing
         * registration. Payload: [pk(32)].
         * Reply: HANDLE_RESULT with status=0 and payload
         *        [status(1)][reason_len(1)][reason][handle_len(1)][handle]
         * (the standard pk(32) suffix is replaced by handle_len + handle).
         */
        if (clen < 32) {
            send_handle_result(fd, room, room_len, 2, "missing pk", NULL);
            return 1;
        }
        char handle[64];
        int rc = server_db_lookup_handle_by_pk(cipher, handle, sizeof(handle));
        if (rc == 0) {
            /* Build custom payload manually since send_handle_result writes
             * pk(32) instead of handle_len+handle. */
            uint8_t  payload[256];
            size_t   payload_len = 0;
            payload[payload_len++] = 0;          /* status = ok */
            const char *reason     = "ok";
            uint8_t reason_len     = (uint8_t)strlen(reason);
            payload[payload_len++] = reason_len;
            memcpy(payload + payload_len, reason, reason_len);
            payload_len += reason_len;
            uint8_t handle_len = (uint8_t)strlen(handle);
            payload[payload_len++] = handle_len;
            memcpy(payload + payload_len, handle, handle_len);
            payload_len += handle_len;

            static const char *kSrvName = "server";
            uint16_t name_len = (uint16_t)strlen(kSrvName);
            uint8_t  nonce[CRYPTO_NPUBBYTES];
            memset(nonce, 0, sizeof(nonce));
            size_t frame_len = 2 + room_len + 2 + name_len + 2
                             + CRYPTO_NPUBBYTES + 1 + 4 + payload_len;
            uint8_t *frame = (uint8_t *)malloc(frame_len);
            if (frame) {
                uint8_t *w = frame;
                wr_u16(w, room_len);            w += 2;
                memcpy(w, room, room_len);      w += room_len;
                wr_u16(w, name_len);            w += 2;
                memcpy(w, kSrvName, name_len);  w += name_len;
                wr_u16(w, CRYPTO_NPUBBYTES);    w += 2;
                memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
                *w++ = (uint8_t)MSG_TYPE_HANDLE_RESULT;
                wr_u32(w, (uint32_t)payload_len); w += 4;
                memcpy(w, payload, payload_len);
                send_all(fd, frame, frame_len);
                free(frame);
            }
        } else if (rc == 1) {
            send_handle_result(fd, room, room_len, 1, "not found", NULL);
        } else {
            send_handle_result(fd, room, room_len, 3, "server error", NULL);
        }
        return 1;
    }

    if (type == MSG_TYPE_BLOB_PUT) {
        /* payload: [pk(32)][sig(64)][type_len(1)][type][cipher_len(4)][cipher] */
        if (clen < 32 + 64 + 1 + 4) {
            send_handle_result(fd, room, room_len, 2, "blob put too short", NULL);
            return 1;
        }
        const uint8_t *pk        = cipher;
        const uint8_t *sig       = cipher + 32;
        uint8_t        type_len  = cipher[32 + 64];
        if (clen < (uint32_t)32 + 64 + 1 + type_len + 4) {
            send_handle_result(fd, room, room_len, 2, "truncated type", NULL);
            return 1;
        }
        const uint8_t *type_buf  = cipher + 32 + 64 + 1;
        uint32_t       cipher_len = rd_u32(cipher + 32 + 64 + 1 + type_len);
        if (clen < (uint32_t)32 + 64 + 1 + type_len + 4 + cipher_len) {
            send_handle_result(fd, room, room_len, 2, "truncated cipher", NULL);
            return 1;
        }
        const uint8_t *cipher_data = cipher + 32 + 64 + 1 + type_len + 4;

        /* Sig covers (type_bytes || cipher_bytes) — proves the requester
         * owns identity_pk before we let them write a blob under it. */
        size_t signed_len = (size_t)type_len + cipher_len;
        uint8_t *signed_buf = (uint8_t *)malloc(signed_len);
        if (!signed_buf) {
            send_handle_result(fd, room, room_len, 3, "oom", NULL);
            return 1;
        }
        memcpy(signed_buf, type_buf, type_len);
        memcpy(signed_buf + type_len, cipher_data, cipher_len);
        int sig_ok = crypto_sign_verify_detached(sig, signed_buf, signed_len, pk);
        free(signed_buf);
        if (sig_ok != 0) {
            send_handle_result(fd, room, room_len, 2, "bad signature", NULL);
            return 1;
        }

        /* server_db expects a NUL-terminated blob_type string. */
        char type_str[64];
        if (type_len >= sizeof(type_str)) type_len = sizeof(type_str) - 1;
        memcpy(type_str, type_buf, type_len);
        type_str[type_len] = '\0';

        if (server_db_put_blob(pk, type_str, cipher_data, cipher_len) == 0) {
            send_handle_result(fd, room, room_len, 0, "ok", NULL);
            printf("[server] blob '%s' stored (%u bytes)\n", type_str, cipher_len);
        } else {
            send_handle_result(fd, room, room_len, 3, "db error", NULL);
        }
        return 1;
    }

    if (type == MSG_TYPE_BLOB_GET) {
        /* payload: [pk(32)][type_len(1)][type] */
        if (clen < 32 + 1) {
            send_handle_result(fd, room, room_len, 2, "blob get too short", NULL);
            return 1;
        }
        const uint8_t *pk       = cipher;
        uint8_t        type_len = cipher[32];
        if (clen < (uint32_t)32 + 1 + type_len) {
            send_handle_result(fd, room, room_len, 2, "truncated type", NULL);
            return 1;
        }
        char type_str[64];
        if (type_len >= sizeof(type_str)) type_len = sizeof(type_str) - 1;
        memcpy(type_str, cipher + 33, type_len);
        type_str[type_len] = '\0';

        uint8_t *blob = NULL; size_t blob_len = 0;
        int rc = server_db_get_blob(pk, type_str, &blob, &blob_len);
        if (rc != 0) {
            send_handle_result(fd, room, room_len,
                               rc == 1 ? 1 : 3,
                               rc == 1 ? "not found" : "db error", NULL);
            return 1;
        }

        /* Build a BLOB_RESULT frame with [status=0][reason_len=2 "ok"]"ok"
         * [cipher_len(4)][cipher]. We can't reuse send_handle_result because
         * it doesn't carry an arbitrary cipher payload. Inline below. */
        uint8_t  reason_len = 2;
        size_t   payload_len = 1 + 1 + reason_len + 4 + blob_len;
        uint8_t *payload     = (uint8_t *)malloc(payload_len);
        if (!payload) { free(blob); return 1; }
        payload[0] = 0;
        payload[1] = reason_len;
        memcpy(payload + 2, "ok", reason_len);
        wr_u32(payload + 2 + reason_len, (uint32_t)blob_len);
        memcpy(payload + 2 + reason_len + 4, blob, blob_len);

        static const char *kSrvName = "server";
        uint16_t name_len = (uint16_t)strlen(kSrvName);
        uint8_t  nonce[CRYPTO_NPUBBYTES];
        memset(nonce, 0, sizeof(nonce));
        size_t frame_len = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + payload_len;
        uint8_t *frame = (uint8_t *)malloc(frame_len);
        if (!frame) { free(blob); free(payload); return 1; }
        uint8_t *w = frame;
        wr_u16(w, room_len);                w += 2;
        memcpy(w, room, room_len);          w += room_len;
        wr_u16(w, name_len);                w += 2;
        memcpy(w, kSrvName, name_len);      w += name_len;
        wr_u16(w, CRYPTO_NPUBBYTES);        w += 2;
        memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
        *w++ = (uint8_t)MSG_TYPE_BLOB_RESULT;
        wr_u32(w, (uint32_t)payload_len);   w += 4;
        memcpy(w, payload, payload_len);
        send_all(fd, frame, frame_len);
        free(frame);
        free(payload);
        free(blob);
        return 1;
    }

    return 0;  /* not a handle / blob command */
}

/**
 * Server-side handler for room-scoped service commands that need access
 * to the client roster: ROOM_INFO_REQUEST and PING. Kept separate from
 * try_handle_command because that one only sees the single client's fd
 * and has no way to count peers in the room.
 *
 * Returns 1 if the frame was handled (caller must skip broadcast/registration),
 *         0 otherwise.
 */
static int try_room_command(sock_t fd,
                            const uint8_t *frame, size_t flen,
                            const client_t *clients, int nclients) {
    if (flen < 2) return 0;
    uint16_t room_len = rd_u16(frame);
    if (flen < (size_t)2 + room_len + 2) return 0;
    uint16_t name_len = rd_u16(frame + 2 + room_len);
    size_t off = 2 + room_len + 2 + name_len;
    if (flen < off + 2) return 0;
    uint16_t nonce_len = rd_u16(frame + off);
    off += 2 + nonce_len;
    if (flen < off + 1 + 4) return 0;
    uint8_t  type = frame[off];
    /* clen unused but parsed for consistency with try_handle_command */
    (void)rd_u32(frame + off + 1);
    const char *room = (const char *)(frame + 2);

    if (type == MSG_TYPE_PING) {
        /* No reply needed — caller already bumped last_seen on read_frame. */
        return 1;
    }

    if (type == MSG_TYPE_ROOM_INFO_REQUEST) {
        /* Count non-media members already attached to the room. */
        uint32_t count = 0;
        for (int i = 0; i < nclients; i++) {
            if (clients[i].is_media_relay) continue;
            if (clients[i].room[0] == '\0') continue;
            if (strncmp(clients[i].room, room, room_len) == 0
                && clients[i].room[room_len] == '\0') {
                count++;
            }
        }

        /* Reply: zero-nonce service msg with payload [exists(1)][count(4 LE)]. */
        static const char *kSrvName = "server";
        uint16_t  srv_name_len = (uint16_t)strlen(kSrvName);
        uint8_t   nonce[CRYPTO_NPUBBYTES];
        memset(nonce, 0, sizeof(nonce));

        uint8_t payload[1 + 4];
        payload[0] = (count > 0) ? 1 : 0;
        wr_u32(payload + 1, count);

        size_t frame_len = 2 + room_len + 2 + srv_name_len + 2
                         + CRYPTO_NPUBBYTES + 1 + 4 + sizeof(payload);
        uint8_t *out = (uint8_t *)malloc(frame_len);
        if (!out) return 1;
        uint8_t *w = out;
        wr_u16(w, room_len);                 w += 2;
        memcpy(w, room, room_len);           w += room_len;
        wr_u16(w, srv_name_len);             w += 2;
        memcpy(w, kSrvName, srv_name_len);   w += srv_name_len;
        wr_u16(w, CRYPTO_NPUBBYTES);         w += 2;
        memcpy(w, nonce, CRYPTO_NPUBBYTES);  w += CRYPTO_NPUBBYTES;
        *w++ = (uint8_t)MSG_TYPE_ROOM_INFO_RESULT;
        wr_u32(w, (uint32_t)sizeof(payload)); w += 4;
        memcpy(w, payload, sizeof(payload));
        send_all(fd, out, frame_len);
        free(out);
        return 1;
    }

    return 0;
}

static void set_tcp_keepalive(sock_t fd) {
#ifdef _WIN32
    DWORD yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&yes, sizeof(yes));
#else
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    int idle = 60;   /* start probing after 60s of silence */
    int intvl = 10;  /* 10s between probes */
    int cnt = 3;     /* 3 failed probes = dead */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

static void send_error_and_close(sock_t fd, const char *room, uint16_t room_len,
                                 const char *error_msg) {
    uint16_t name_len = (uint16_t)strlen("server");
    uint8_t nonce[CRYPTO_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));
    size_t msg_len = strlen(error_msg);
    size_t frame_len = 2 + room_len + 2 + name_len + 2 + CRYPTO_NPUBBYTES + 1 + 4 + msg_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) { close_socket(fd); return; }
    uint8_t *w = frame;
    wr_u16(w, room_len); w += 2;
    memcpy(w, room, room_len); w += room_len;
    wr_u16(w, name_len); w += 2;
    memcpy(w, "server", name_len); w += name_len;
    wr_u16(w, CRYPTO_NPUBBYTES); w += 2;
    memcpy(w, nonce, CRYPTO_NPUBBYTES); w += CRYPTO_NPUBBYTES;
    *w++ = (uint8_t)MSG_TYPE_TEXT;
    wr_u32(w, (uint32_t)msg_len); w += 4;
    memcpy(w, error_msg, msg_len);
    send_all(fd, frame, frame_len);
    free(frame);
    close_socket(fd);
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
    /* When stdout is redirected to a file or systemd journal it switches to
     * block buffering by default — operational logs ([server] new connection,
     * [server] idle kick, etc.) then sit in a 4KB buffer for hours. Force
     * line buffering so each printf shows up immediately. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    sock_t listener = server_listen(port);
    printf("[server] listening on 0.0.0.0:%u (TCP)\n", port);

    /* Phase B-2: open the handles + user_blobs DB. Failure here is non-fatal —
     * the relay still works without persistent state, just no handle
     * registration is possible. */
    if (server_db_open(NULL) < 0) {
        printf("[server] WARN: server-db unavailable, handle commands will be rejected\n");
    }

    /* Create UDP socket for relay, bound to same port */
    sock_t udp_sock = (sock_t)socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket");
        close_socket(listener);
        return;
    }
    {
        struct sockaddr_in udp_bind;
        memset(&udp_bind, 0, sizeof(udp_bind));
        udp_bind.sin_family = AF_INET;
        udp_bind.sin_addr.s_addr = htonl(INADDR_ANY);
        udp_bind.sin_port = htons(port);
        if (bind(udp_sock, (struct sockaddr *)&udp_bind, sizeof(udp_bind)) < 0) {
            perror("UDP bind");
            close_socket(udp_sock);
            close_socket(listener);
            return;
        }
    }
    printf("[server] UDP relay on port %u\n", port);

    client_t clients[MAX_CLIENTS];
    int nclients = 0;
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        FD_SET(udp_sock, &rfds);
        sock_t maxfd = listener;
        if (udp_sock > maxfd) maxfd = udp_sock;
        for (int i = 0; i < nclients; i++) {
            FD_SET(clients[i].fd, &rfds);
            if (clients[i].fd > maxfd) maxfd = clients[i].fd;
        }
        /* Wake up at least once per minute so the idle scan below runs even
         * when nobody is sending traffic. */
        struct timeval tv;
        tv.tv_sec = 60;
        tv.tv_usec = 0;
        int r = select((int)(maxfd + 1), &rfds, NULL, NULL, &tv);
        if (r < 0) { perror("select"); break; }

        /* Idle scan: kick anyone we haven't heard from in IDLE_TIMEOUT_SEC
         * seconds. Application-level heartbeat via MSG_TYPE_PING (sent every
         * 60s by clients) keeps an active connection alive; if a client
         * crashes, gets killed, or its NAT silently drops the flow we
         * release the slot here without waiting for TCP keepalive. */
        time_t now = time(NULL);
        for (int i = 0; i < nclients; i++) {
            if (now - clients[i].last_seen <= IDLE_TIMEOUT_SEC) continue;
            printf("[server] idle kick: %s@%s silent for %lds\n",
                   clients[i].name[0] ? clients[i].name : "?",
                   clients[i].room[0] ? clients[i].room : "?",
                   (long)(now - clients[i].last_seen));
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
            if (dropped_room[0] != '\0') {
                send_user_list(clients, nclients, dropped_room);
            }
        }
        if (r == 0) continue;  /* select timeout, no fds ready */

        /* Handle UDP relay */
        if (FD_ISSET(udp_sock, &rfds)) {
            uint8_t ubuf[65536];
            struct sockaddr_in src;
            socklen_t slen = sizeof(src);
            int ulen = recvfrom(udp_sock, (char *)ubuf, sizeof(ubuf), 0,
                                (struct sockaddr *)&src, &slen);
            if (ulen > 0) {
                if (ubuf[0] == UDP_REG_MAGIC && ulen >= 5) {
                    /* Registration: [0xFE][2 room_len LE][room][2 name_len LE][name] */
                    uint16_t reg_room_len = rd_u16(ubuf + 1);
                    if (3 + reg_room_len + 2 <= (size_t)ulen) {
                        uint16_t reg_name_len = rd_u16(ubuf + 3 + reg_room_len);
                        if (3 + reg_room_len + 2 + reg_name_len <= (size_t)ulen) {
                            char reg_room[MAX_ROOM], reg_name[MAX_NAME];
                            size_t rl = reg_room_len < MAX_ROOM - 1 ? reg_room_len : MAX_ROOM - 1;
                            size_t nl = reg_name_len < MAX_NAME - 1 ? reg_name_len : MAX_NAME - 1;
                            memcpy(reg_room, ubuf + 3, rl);
                            reg_room[rl] = '\0';
                            memcpy(reg_name, ubuf + 3 + reg_room_len + 2, nl);
                            reg_name[nl] = '\0';

                            /* Find matching TCP client by room+name */
                            for (int i = 0; i < nclients; i++) {
                                if (clients[i].room[0] != '\0' && clients[i].name[0] != '\0' &&
                                    strcmp(clients[i].room, reg_room) == 0 &&
                                    strcmp(clients[i].name, reg_name) == 0) {
                                    clients[i].udp_addr = src;
                                    clients[i].udp_registered = 1;
                                    printf("[server] UDP registered: %s@%s from %s:%u\n",
                                           reg_name, reg_room,
                                           inet_ntoa(src.sin_addr), ntohs(src.sin_port));
                                    /* Send ACK back: [0xFD] — test UDP reachability */
                                    {
                                        uint8_t ack = 0xFD;
                                        sendto(udp_sock, (const char *)&ack, 1, 0,
                                               (struct sockaddr *)&src, sizeof(src));
                                    }
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    /* Media relay: find sender by address, forward to other room members */
                    int sender_idx = -1;
                    for (int i = 0; i < nclients; i++) {
                        if (clients[i].udp_registered &&
                            clients[i].udp_addr.sin_addr.s_addr == src.sin_addr.s_addr &&
                            clients[i].udp_addr.sin_port == src.sin_port) {
                            sender_idx = i;
                            break;
                        }
                    }
                    if (sender_idx >= 0) {
                        const char *sender_room = clients[sender_idx].room;
                        int forwarded = 0;
                        for (int i = 0; i < nclients; i++) {
                            if (i == sender_idx) continue;
                            if (!clients[i].udp_registered) continue;
                            if (strcmp(clients[i].room, sender_room) != 0) continue;
                            int sr = sendto(udp_sock, (const char *)ubuf, ulen, 0,
                                   (struct sockaddr *)&clients[i].udp_addr,
                                   sizeof(clients[i].udp_addr));
                            if (sr > 0) forwarded++;
                        }
                        /* Log relay activity */
                        static long relay_count = 0;
                        relay_count++;
                        if (relay_count <= 20 || relay_count % 500 == 0) {
                            printf("[server] UDP relay #%ld: %s (type=0x%02x, %d bytes) -> %d peer(s)\n",
                                   relay_count, clients[sender_idx].name,
                                   ubuf[0], ulen, forwarded);
                        }
                    } else {
                        /* Packet from unregistered UDP source */
                        static int unreg_warn_count = 0;
                        if (unreg_warn_count < 10) {
                            printf("[server] UDP drop: unregistered %s:%u (type=0x%02x, %d bytes)\n",
                                   inet_ntoa(src.sin_addr), ntohs(src.sin_port),
                                   ubuf[0], ulen);
                            unreg_warn_count++;
                        }
                    }
                }
            }
        }

        if (FD_ISSET(listener, &rfds)) {
            struct sockaddr_in cli;
            socklen_t cl = sizeof(cli);
            sock_t c = accept(listener, (struct sockaddr*)&cli, &cl);
            if (c >= 0) {
                if (nclients < MAX_CLIENTS) {
                    set_tcp_keepalive(c);
                    clients[nclients].fd = c;
                    clients[nclients].room[0] = '\0';
                    clients[nclients].name[0] = '\0';
                    clients[nclients].udp_registered = 0;
                    clients[nclients].is_media_relay = 0;
                    clients[nclients].last_seen = time(NULL);
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
            clients[i].last_seen = time(NULL);

            /* Phase B-2: handle-registry commands are out-of-band — they
             * don't belong to any chat room. Process and reply right away
             * without registering this client into a room or broadcasting. */
            if (try_handle_command(clients[i].fd, frame, flen)) {
                free(frame);
                continue;
            }
            /* Phase B-8: ROOM_INFO probe (AUTO connect) and PING (heartbeat)
             * also bypass registration and broadcast. Must run AFTER
             * last_seen update so the PING actually counts as activity. */
            if (try_room_command(clients[i].fd, frame, flen, clients, nclients)) {
                free(frame);
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
                // Check message type to detect media relay connections
                uint16_t nonce_len_val = rd_u16(frame + 2 + room_len + 2 + name_len);
                uint8_t msg_type = frame[2 + room_len + 2 + name_len + 2 + nonce_len_val];
                int is_media = (msg_type == MSG_TYPE_MEDIA_RELAY);

                // Проверяем уникальность имени в той же комнате (skip for media relay)
                int name_exists = 0;
                if (!is_media) {
                    for (int j = 0; j < nclients; j++) {
                        if (i == j) continue;
                        if (clients[j].name[0] != '\0' && clients[j].room[0] != '\0' &&
                            !clients[j].is_media_relay) {
                            if (strncmp(clients[j].room, room, room_len) == 0 &&
                                clients[j].room[room_len] == '\0' &&
                                strncmp(clients[j].name, name, name_len) == 0 &&
                                clients[j].name[name_len] == '\0') {
                                name_exists = 1;
                                break;
                            }
                        }
                    }
                }

                if (name_exists) {
                    printf("[server] client rejected: name '%.*s' already exists in room '%.*s'\n",
                           (int)name_len, name, (int)room_len, room);
                    send_error_and_close(clients[i].fd, room, room_len,
                                         "Name already taken in this room");
                    clients[i] = clients[nclients - 1];
                    nclients--;
                    i--;
                    free(frame);
                    continue;
                }

                size_t nl = name_len < MAX_NAME - 1 ? name_len : MAX_NAME - 1;
                memcpy(clients[i].name, name, nl);
                clients[i].name[nl] = '\0';
                clients[i].is_media_relay = is_media;

                if (is_media) {
                    printf("[server] media relay registered: name='%s', room='%s'\n",
                           clients[i].name, clients[i].room);
                } else {
                    printf("[server] client registered: name='%s', room='%s'\n",
                           clients[i].name, clients[i].room);
                    // Отправляем обновленный список участников всем в комнате
                    send_user_list(clients, nclients, clients[i].room);
                }
            }
            broadcast(clients, &nclients, clients[i].room, frame, flen, clients[i].fd);
            free(frame);
        }
    }
    close_socket(udp_sock);
    close_socket(listener);
    server_db_close();
#ifdef _WIN32
    WSACleanup();
#endif
}