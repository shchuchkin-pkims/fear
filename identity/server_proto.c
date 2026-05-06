#include "server_proto.h"
#include "identity.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int sock_t;
typedef int ssize_t;
#define close_socket(s) closesocket(s)
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int sock_t;
#define close_socket(s) close(s)
#endif

/* Frame layout (matches client-console/src/server.c):
 *   [2] room_len LE
 *   [N] room
 *   [2] name_len LE
 *   [M] name
 *   [2] nonce_len LE       (12 for AES-GCM zero-nonce service msgs)
 *   [12] nonce             (all zeros)
 *   [1] type
 *   [4] cipher_len LE
 *   [C] cipher (raw payload for service messages)
 */
#define SP_NONCE_LEN  12
#define SP_ROOM       "__svc__"
#define SP_NAME       "__svc__"

/* MSG_TYPE_* values — keep in sync with client-console/include/common.h */
#define MT_REGISTER_HANDLE       20
#define MT_LOOKUP_HANDLE         21
#define MT_HANDLE_RESULT         22
#define MT_BLOB_PUT              23
#define MT_BLOB_GET              24
#define MT_BLOB_RESULT           25
#define MT_LOOKUP_HANDLE_BY_PK   26

/* ===== little-endian primitives ===== */
static void wr_u16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr_u32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
                                              p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd_u32(const uint8_t *p) { return (uint32_t)(p[0] | (p[1] << 8) |
                                                              (p[2] << 16) | (p[3] << 24)); }

/* ===== socket helpers ===== */

static sock_t connect_tcp(const char *host, uint16_t port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return (sock_t)-1;

    sock_t s = (sock_t)-1;
    for (struct addrinfo *it = res; it; it = it->ai_next) {
        s = (sock_t)socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (s < 0) continue;
        if (connect(s, it->ai_addr, (int)it->ai_addrlen) == 0) break;
        close_socket(s); s = (sock_t)-1;
    }
    freeaddrinfo(res);
    return s;
}

static int write_full(sock_t s, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = send(s, (const char *)p, (int)n, 0);
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int read_full(sock_t s, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = recv(s, (char *)p, (int)n, 0);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* Build a service frame and send. Caller frees nothing. */
static int send_frame(sock_t s, uint8_t type,
                      const uint8_t *payload, uint32_t payload_len) {
    uint16_t room_len = (uint16_t)strlen(SP_ROOM);
    uint16_t name_len = (uint16_t)strlen(SP_NAME);
    size_t   total    = 2 + room_len + 2 + name_len + 2 + SP_NONCE_LEN + 1 + 4 + payload_len;
    uint8_t *frame    = (uint8_t *)malloc(total);
    if (!frame) return -1;

    uint8_t *w = frame;
    wr_u16(w, room_len);                w += 2;
    memcpy(w, SP_ROOM, room_len);       w += room_len;
    wr_u16(w, name_len);                w += 2;
    memcpy(w, SP_NAME, name_len);       w += name_len;
    wr_u16(w, SP_NONCE_LEN);            w += 2;
    memset(w, 0, SP_NONCE_LEN);         w += SP_NONCE_LEN;
    *w++ = type;
    wr_u32(w, payload_len);             w += 4;
    memcpy(w, payload, payload_len);

    int rc = write_full(s, frame, total);
    free(frame);
    return rc;
}

/* Read one frame and return its (type, cipher) parts. Cipher is malloc'd. */
static int recv_frame(sock_t s, uint8_t *type_out, uint8_t **cipher_out, uint32_t *clen_out) {
    uint8_t hdr[2];
    if (read_full(s, hdr, 2) < 0) return -1;
    uint16_t room_len = rd_u16(hdr);
    uint8_t scratch[1024];
    if (room_len > sizeof(scratch)) return -1;
    if (read_full(s, scratch, room_len) < 0) return -1;

    if (read_full(s, hdr, 2) < 0) return -1;
    uint16_t name_len = rd_u16(hdr);
    if (name_len > sizeof(scratch)) return -1;
    if (read_full(s, scratch, name_len) < 0) return -1;

    if (read_full(s, hdr, 2) < 0) return -1;
    uint16_t nonce_len = rd_u16(hdr);
    if (nonce_len > sizeof(scratch)) return -1;
    if (read_full(s, scratch, nonce_len) < 0) return -1;

    uint8_t type;
    if (read_full(s, &type, 1) < 0) return -1;
    uint8_t lenbuf[4];
    if (read_full(s, lenbuf, 4) < 0) return -1;
    uint32_t clen = rd_u32(lenbuf);
    if (clen > 16 * 1024 * 1024) return -1;     /* sanity cap: 16 MB */

    uint8_t *cipher = (uint8_t *)malloc(clen ? clen : 1);
    if (!cipher) return -1;
    if (clen > 0 && read_full(s, cipher, clen) < 0) {
        free(cipher);
        return -1;
    }
    *type_out = type;
    *cipher_out = cipher;
    *clen_out = clen;
    return 0;
}

/* status from the first byte of HANDLE_RESULT/BLOB_RESULT payload */
static sp_status_t status_from_byte(uint8_t b) {
    switch (b) {
        case 0: return SP_OK;
        case 1: return SP_NOT_FOUND;
        case 2: return SP_INVALID;
        case 3: return SP_SERVER_ERROR;
        default: return SP_BAD_REPLY;
    }
}

/* ===== High-level commands ===== */

sp_status_t sp_lookup_handle(const char *host, uint16_t port,
                             const char *handle, uint8_t pk_out[32]) {
    if (!host || !handle || !pk_out) return SP_INVALID;
    size_t hlen = strlen(handle);
    if (hlen < 1 || hlen > 255) return SP_INVALID;

    sock_t s = connect_tcp(host, port);
    if (s < 0) return SP_NETWORK_ERROR;

    uint8_t payload[260];
    payload[0] = (uint8_t)hlen;
    memcpy(payload + 1, handle, hlen);
    if (send_frame(s, MT_LOOKUP_HANDLE, payload, (uint32_t)(1 + hlen)) < 0) {
        close_socket(s); return SP_NETWORK_ERROR;
    }

    uint8_t reply_type;
    uint8_t *cipher = NULL;
    uint32_t clen = 0;
    if (recv_frame(s, &reply_type, &cipher, &clen) < 0) {
        close_socket(s); return SP_NETWORK_ERROR;
    }
    close_socket(s);
    if (reply_type != MT_HANDLE_RESULT || clen < 2) { free(cipher); return SP_BAD_REPLY; }

    uint8_t status = cipher[0];
    uint8_t reason_len = cipher[1];
    sp_status_t st = status_from_byte(status);
    if (st == SP_OK) {
        if (clen >= 2u + reason_len + 32u) {
            memcpy(pk_out, cipher + 2 + reason_len, 32);
        } else {
            st = SP_BAD_REPLY;
        }
    }
    free(cipher);
    return st;
}

sp_status_t sp_lookup_handle_by_pk(const char *host, uint16_t port,
                                   const uint8_t pk[32],
                                   char *handle_out, size_t handle_cap) {
    if (!host || !pk || !handle_out || handle_cap < 2) return SP_INVALID;

    sock_t s = connect_tcp(host, port);
    if (s < 0) return SP_NETWORK_ERROR;

    /* payload: [pk(32)] */
    if (send_frame(s, MT_LOOKUP_HANDLE_BY_PK, pk, 32) < 0) {
        close_socket(s); return SP_NETWORK_ERROR;
    }

    uint8_t reply_type;
    uint8_t *cipher = NULL;
    uint32_t clen = 0;
    if (recv_frame(s, &reply_type, &cipher, &clen) < 0) {
        close_socket(s); return SP_NETWORK_ERROR;
    }
    close_socket(s);
    if (reply_type != MT_HANDLE_RESULT || clen < 2) { free(cipher); return SP_BAD_REPLY; }

    uint8_t status     = cipher[0];
    uint8_t reason_len = cipher[1];
    sp_status_t st = status_from_byte(status);
    if (st == SP_OK) {
        /* Layout for OK reply: [0][reason_len][reason][handle_len(1)][handle] */
        if (clen >= 2u + reason_len + 1u) {
            uint8_t handle_len = cipher[2 + reason_len];
            if (handle_len > 0 && (size_t)handle_len < handle_cap
                && clen >= 2u + reason_len + 1u + handle_len) {
                memcpy(handle_out, cipher + 2 + reason_len + 1, handle_len);
                handle_out[handle_len] = '\0';
            } else {
                st = SP_BAD_REPLY;
            }
        } else {
            st = SP_BAD_REPLY;
        }
    }
    free(cipher);
    return st;
}

sp_status_t sp_register_handle(const char *host, uint16_t port,
                               const char *handle,
                               const uint8_t pk[32], const uint8_t sk[64]) {
    if (!host || !handle || !pk || !sk) return SP_INVALID;
    size_t hlen = strlen(handle);
    if (hlen < 1 || hlen > 255) return SP_INVALID;

    /* sig over the handle bytes — proves owner of pk */
    uint8_t sig[64];
    if (identity_sign((const uint8_t *)handle, hlen, sk, sig) != 0) {
        return SP_SERVER_ERROR;
    }

    /* payload: [pk(32)][sig(64)][handle_len(1)][handle] */
    uint8_t payload[32 + 64 + 1 + 256];
    memcpy(payload, pk, 32);
    memcpy(payload + 32, sig, 64);
    payload[96] = (uint8_t)hlen;
    memcpy(payload + 97, handle, hlen);
    uint32_t plen = (uint32_t)(32 + 64 + 1 + hlen);

    sock_t s = connect_tcp(host, port);
    if (s < 0) return SP_NETWORK_ERROR;
    if (send_frame(s, MT_REGISTER_HANDLE, payload, plen) < 0) {
        close_socket(s); return SP_NETWORK_ERROR;
    }
    uint8_t reply_type;
    uint8_t *cipher = NULL; uint32_t clen = 0;
    int rc = recv_frame(s, &reply_type, &cipher, &clen);
    close_socket(s);
    if (rc < 0) return SP_NETWORK_ERROR;
    if (reply_type != MT_HANDLE_RESULT || clen < 1) { free(cipher); return SP_BAD_REPLY; }
    sp_status_t st = status_from_byte(cipher[0]);
    free(cipher);
    return st;
}

sp_status_t sp_blob_put(const char *host, uint16_t port,
                        const uint8_t pk[32], const uint8_t sk[64],
                        const char *type,
                        const uint8_t *cipher, size_t cipher_len) {
    if (!host || !pk || !sk || !type || (cipher_len > 0 && !cipher)) return SP_INVALID;
    size_t tlen = strlen(type);
    if (tlen < 1 || tlen > 255) return SP_INVALID;
    if (cipher_len > 1024 * 1024) return SP_INVALID;     /* 1 MB cap */

    /* sig over (type || cipher) — proves owner of pk */
    uint8_t *signed_buf = (uint8_t *)malloc(tlen + cipher_len);
    if (!signed_buf) return SP_SERVER_ERROR;
    memcpy(signed_buf, type, tlen);
    memcpy(signed_buf + tlen, cipher, cipher_len);
    uint8_t sig[64];
    int sg = identity_sign(signed_buf, tlen + cipher_len, sk, sig);
    free(signed_buf);
    if (sg != 0) return SP_SERVER_ERROR;

    /* payload: [pk(32)][sig(64)][type_len(1)][type][cipher_len(4)][cipher] */
    size_t plen = 32 + 64 + 1 + tlen + 4 + cipher_len;
    uint8_t *payload = (uint8_t *)malloc(plen);
    if (!payload) return SP_SERVER_ERROR;
    size_t o = 0;
    memcpy(payload + o, pk, 32);                          o += 32;
    memcpy(payload + o, sig, 64);                         o += 64;
    payload[o++] = (uint8_t)tlen;
    memcpy(payload + o, type, tlen);                      o += tlen;
    wr_u32(payload + o, (uint32_t)cipher_len);            o += 4;
    if (cipher_len) memcpy(payload + o, cipher, cipher_len);

    sock_t s = connect_tcp(host, port);
    if (s < 0) { free(payload); return SP_NETWORK_ERROR; }
    int sf = send_frame(s, MT_BLOB_PUT, payload, (uint32_t)plen);
    free(payload);
    if (sf < 0) { close_socket(s); return SP_NETWORK_ERROR; }

    uint8_t reply_type;
    uint8_t *resp_cipher = NULL; uint32_t resp_clen = 0;
    int rc = recv_frame(s, &reply_type, &resp_cipher, &resp_clen);
    close_socket(s);
    if (rc < 0) return SP_NETWORK_ERROR;
    if (reply_type != MT_BLOB_RESULT || resp_clen < 1) { free(resp_cipher); return SP_BAD_REPLY; }
    sp_status_t st = status_from_byte(resp_cipher[0]);
    free(resp_cipher);
    return st;
}

sp_status_t sp_blob_get(const char *host, uint16_t port,
                        const uint8_t pk[32], const char *type,
                        uint8_t **out, size_t *out_len) {
    if (!host || !pk || !type || !out || !out_len) return SP_INVALID;
    *out = NULL; *out_len = 0;
    size_t tlen = strlen(type);
    if (tlen < 1 || tlen > 255) return SP_INVALID;

    /* payload: [pk(32)][type_len(1)][type] */
    uint8_t payload[32 + 1 + 256];
    memcpy(payload, pk, 32);
    payload[32] = (uint8_t)tlen;
    memcpy(payload + 33, type, tlen);

    sock_t s = connect_tcp(host, port);
    if (s < 0) return SP_NETWORK_ERROR;
    if (send_frame(s, MT_BLOB_GET, payload, (uint32_t)(33 + tlen)) < 0) {
        close_socket(s); return SP_NETWORK_ERROR;
    }
    uint8_t reply_type;
    uint8_t *resp = NULL; uint32_t rlen = 0;
    int rc = recv_frame(s, &reply_type, &resp, &rlen);
    close_socket(s);
    if (rc < 0) return SP_NETWORK_ERROR;
    if (reply_type != MT_BLOB_RESULT || rlen < 2) { free(resp); return SP_BAD_REPLY; }

    uint8_t status = resp[0];
    uint8_t reason_len = resp[1];
    sp_status_t st = status_from_byte(status);
    if (st == SP_OK) {
        size_t off = 2 + reason_len;
        if (rlen < off + 4) { free(resp); return SP_BAD_REPLY; }
        uint32_t clen = rd_u32(resp + off);
        if (rlen < off + 4 + clen) { free(resp); return SP_BAD_REPLY; }
        uint8_t *blob = (uint8_t *)malloc(clen ? clen : 1);
        if (!blob) { free(resp); return SP_SERVER_ERROR; }
        if (clen) memcpy(blob, resp + off + 4, clen);
        *out = blob;
        *out_len = clen;
    }
    free(resp);
    return st;
}
