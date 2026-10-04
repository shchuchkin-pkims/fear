/**
 * @file identity_backup.h
 * @brief Encrypted identity backup format for F.E.A.R. messenger
 *
 * Self-contained portable backup of an Ed25519 identity, encrypted under
 * a user-supplied passphrase. Used for:
 *   - "Export identity" (.fbk file the user can stash anywhere)
 *   - QR-code transport between devices (same blob, base64-encoded)
 *
 * Wire format (binary):
 *   [4 ] magic        "FBK1"
 *   [1 ] version      = 0x01
 *   [1 ] reserved     = 0x00
 *   [16] kdf_salt     (argon2id, libsodium crypto_pwhash)
 *   [8 ] kdf_ops      uint64 BE (libsodium opslimit)
 *   [8 ] kdf_mem      uint64 BE (libsodium memlimit, bytes)
 *   [24] box_nonce    (crypto_secretbox_easy)
 *   [N ] ciphertext   (XSalsa20-Poly1305, plaintext = JSON)
 *
 * Plaintext JSON (UTF-8, compact):
 *   {"v":1,"sk":"<b64url>","pk":"<b64url>","ts":<unix>}
 *
 * Forward-compat: extra JSON keys are ignored by older readers; bumping
 * the binary version field is reserved for incompatible header changes.
 */
#ifndef FEAR_IDENTITY_BACKUP_H
#define FEAR_IDENTITY_BACKUP_H

#include "identity.h"

#define IDENTITY_BACKUP_MAGIC      "FBK1"
#define IDENTITY_BACKUP_MAGIC_LEN  4
#define IDENTITY_BACKUP_VERSION    0x01
#define IDENTITY_BACKUP_HEADER_LEN (4 + 1 + 1 + 16 + 8 + 8 + 24)  /* 62 bytes */

/**
 * Recommended argon2id parameters. Tuned for ~100ms on a modern phone,
 * ~30ms on a desktop. Both produce a 32-byte derived key.
 */
#define IDENTITY_BACKUP_OPSLIMIT   3ULL
#define IDENTITY_BACKUP_MEMLIMIT   (64ULL * 1024 * 1024)  /* 64 MB */

/**
 * Encrypt identity to a file under `password`.
 * Caller may supply NULL/zero `created_unix` to use current time.
 * @return 0 on success, -1 on error.
 */
int identity_backup_export(const char *out_path,
                           const uint8_t sk[IDENTITY_SK_BYTES],
                           const uint8_t pk[IDENTITY_PK_BYTES],
                           const char *password);

/**
 * Decrypt identity from a file using `password`.
 * @return 0 on success, -1 on bad password / corrupt file.
 */
int identity_backup_import(const char *in_path,
                           const char *password,
                           uint8_t sk_out[IDENTITY_SK_BYTES],
                           uint8_t pk_out[IDENTITY_PK_BYTES]);

/**
 * Encrypt to a heap-allocated buffer (caller frees with free()).
 * Useful for QR-code text where we want the raw ciphertext bytes.
 * @return 0 on success, -1 on error.
 */
int identity_backup_export_buf(uint8_t **out_buf, size_t *out_len,
                               const uint8_t sk[IDENTITY_SK_BYTES],
                               const uint8_t pk[IDENTITY_PK_BYTES],
                               const char *password);

/**
 * Decrypt from a memory buffer (e.g. base64-decoded QR payload).
 * @return 0 on success, -1 on error.
 */
int identity_backup_import_buf(const uint8_t *buf, size_t buf_len,
                               const char *password,
                               uint8_t sk_out[IDENTITY_SK_BYTES],
                               uint8_t pk_out[IDENTITY_PK_BYTES]);

#endif /* FEAR_IDENTITY_BACKUP_H */
