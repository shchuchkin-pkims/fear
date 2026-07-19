/**
 * @file server_db.h
 * @brief SQLite-backed state for the F.E.A.R. relay server (Phase B-2).
 *
 * The relay was historically stateless; this module gives it a persistent
 * `handles` registry (Mastodon-style `@username` claims keyed to identity_pk)
 * and a `user_blobs` store (for the encrypted-contacts blob in Phase B-3).
 *
 * Schema v1:
 *   handles(handle TEXT PRIMARY KEY, identity_pk BLOB(32) NOT NULL,
 *           claimed_at INTEGER NOT NULL)
 *   user_blobs(identity_pk BLOB NOT NULL, blob_type TEXT NOT NULL,
 *              ciphertext BLOB NOT NULL, updated_at INTEGER NOT NULL,
 *              PRIMARY KEY (identity_pk, blob_type))
 *
 * Path: $FEAR_SERVER_DB or `./fear-server.sqlite` relative to the CWD the
 * server was launched from. Single connection, single-thread (the relay is
 * already single-threaded around its select() loop).
 */
#ifndef FEAR_SERVER_DB_H
#define FEAR_SERVER_DB_H

#include <stddef.h>
#include <stdint.h>

/** Result codes from server_db_register_handle. */
typedef enum {
    HANDLE_REGISTER_OK         = 0,  /* claim recorded */
    HANDLE_REGISTER_CONFLICT   = 1,  /* handle taken by a different identity_pk */
    HANDLE_REGISTER_INVALID    = 2,  /* malformed handle string */
    HANDLE_REGISTER_DB_ERROR   = 3,
} handle_register_result_t;

/**
 * Open / create the server DB file. Idempotent — calling twice is a no-op.
 * @param path Absolute or relative DB path; pass NULL to use the default.
 * @return 0 on success, -1 on error.
 */
int  server_db_open(const char *path);

/** Close the DB. Safe to call without a prior open. */
void server_db_close(void);

/**
 * Validate a handle string.
 * Rules: 3..32 chars; first char alpha; rest alpha/num/underscore/dot/hyphen.
 * Lowercase-only on storage; we don't accept Unicode for now.
 */
int  server_db_handle_is_valid(const char *handle);

/**
 * Register `handle` to `pk`. If the same `pk` already owns it → still OK.
 * If a different `pk` owns it → CONFLICT.
 */
handle_register_result_t server_db_register_handle(
    const char *handle, const uint8_t pk[32]);

/**
 * Look up a handle. Writes the owner's pk into `pk_out` on success.
 * @return 0 on found, 1 on not found, -1 on db error.
 */
int  server_db_lookup_handle(const char *handle, uint8_t pk_out[32]);

/**
 * Reverse lookup — given an identity_pk, return the handle it registered
 * (if any). Used by clients after identity import to detect that a handle
 * is already claimed for them on this server, so the user is not asked
 * to register again.
 *
 * @param pk           32-byte identity public key.
 * @param handle_out   Caller-supplied buffer; receives a NUL-terminated
 *                     handle string on success.
 * @param handle_cap   Capacity of handle_out (>= 64 recommended).
 * @return 0 on found, 1 on not found, -1 on db error.
 */
int  server_db_lookup_handle_by_pk(const uint8_t pk[32],
                                   char *handle_out, size_t handle_cap);

/**
 * Store / replace an encrypted blob for `pk` of kind `blob_type`.
 * Used for the contacts blob (Phase B-3) and any future per-user state.
 * @return 0 on success, -2 if the identity's storage quota is exceeded,
 *         -1 on any other error.
 */
int  server_db_put_blob(const uint8_t pk[32], const char *blob_type,
                        const uint8_t *cipher, size_t cipher_len);

/**
 * Fetch the most recent blob. `out` is malloc'd; caller frees.
 * @return 0 on success, 1 on not found, -1 on db error.
 */
int  server_db_get_blob(const uint8_t pk[32], const char *blob_type,
                        uint8_t **out, size_t *out_len);

#endif
