/**
 * @file server_proto.h
 * @brief Client-side wire helpers for the F.E.A.R. relay's out-of-band
 *        protocol — handle registry (Phase B-2) and per-user blob
 *        storage (Phase B-3).
 *
 * Each function opens a transient TCP socket to host:port, sends one
 * service frame, reads one HANDLE_RESULT or BLOB_RESULT frame, closes.
 * Synchronous and self-contained — no event loop, no Qt deps; safe to
 * call from a worker thread.
 *
 * The frame layout matches client-console/include/common.h byte-for-byte
 * (room/name placeholders, zero nonce, the new MSG_TYPE_* constants).
 */
#ifndef FEAR_SERVER_PROTO_H
#define FEAR_SERVER_PROTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SP_OK             = 0,   /* server returned status=0                       */
    SP_NOT_FOUND      = 1,   /* server returned status=1 (lookup / blob get)   */
    SP_INVALID        = 2,   /* server returned status=2                       */
    SP_SERVER_ERROR   = 3,
    SP_NETWORK_ERROR  = 4,   /* TCP-level failure                              */
    SP_BAD_REPLY      = 5,   /* malformed reply                                */
} sp_status_t;

/**
 * Look up handle owner. On SP_OK, `pk_out` holds the 32-byte identity_pk.
 */
sp_status_t sp_lookup_handle(const char *host, uint16_t port,
                             const char *handle,
                             uint8_t pk_out[32]);

/**
 * Reverse lookup — given an identity_pk, ask the server which handle is
 * registered to it. On SP_OK the handle string is written to `handle_out`
 * as NUL-terminated UTF-8 (caller-allocated, capacity at least 64 bytes).
 * Returns SP_NOT_FOUND when the pk has no registration on this server.
 *
 * Used by clients after `.fbk` / QR identity import to discover the
 * existing handle on the user's behalf, so the ConnectScreen can show
 * the «Already registered as @nick» state without forcing the user to
 * guess their own handle.
 */
sp_status_t sp_lookup_handle_by_pk(const char *host, uint16_t port,
                                   const uint8_t pk[32],
                                   char *handle_out, size_t handle_cap);

/**
 * Register `handle` for `pk` on the relay. The signature is computed
 * locally with `sk` over the handle bytes.
 */
sp_status_t sp_register_handle(const char *host, uint16_t port,
                               const char *handle,
                               const uint8_t pk[32], const uint8_t sk[64]);

/**
 * Write `cipher` into the blob slot `(pk, type)`.
 * Signature computed over (type || cipher) using `sk`.
 */
sp_status_t sp_blob_put(const char *host, uint16_t port,
                        const uint8_t pk[32], const uint8_t sk[64],
                        const char *type,
                        const uint8_t *cipher, size_t cipher_len);

/**
 * Read the blob at slot `(pk, type)`. On SP_OK, `*out` is malloc'd and
 * the caller must free it. Sets `*out_len` accordingly.
 */
sp_status_t sp_blob_get(const char *host, uint16_t port,
                        const uint8_t pk[32], const char *type,
                        uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
