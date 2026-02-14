/**
 * @file identity.h
 * @brief Ed25519 digital identity for F.E.A.R. messenger
 *
 * Provides optional sender authentication via Ed25519 signatures.
 * Uses SSH-like TOFU (Trust On First Use) model:
 * - Users generate a persistent Ed25519 keypair stored locally
 * - Public keys are exchanged in-band (inside encrypted messages/HELLO)
 * - First-seen keys are trusted and stored in known_keys database
 * - Key changes trigger warnings (possible impersonation)
 *
 * All crypto via libsodium. Pure C11, no platform-specific dependencies
 * beyond POSIX/Win32 filesystem calls. Android NDK compatible.
 */

#ifndef FEAR_IDENTITY_H
#define FEAR_IDENTITY_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

/* Ed25519 constants (from libsodium) */
#define IDENTITY_PK_BYTES  crypto_sign_PUBLICKEYBYTES   /* 32 */
#define IDENTITY_SK_BYTES  crypto_sign_SECRETKEYBYTES   /* 64 */
#define IDENTITY_SIG_BYTES crypto_sign_BYTES            /* 64 */

/* Fingerprint: 8 bytes displayed as xx:xx:xx:xx:xx:xx:xx:xx + null */
#define IDENTITY_FINGERPRINT_LEN 24

/* TOFU check results */
typedef enum {
    TOFU_NEW_KEY           = 0,  /* First time seeing this name; key stored and trusted */
    TOFU_KEY_MATCH         = 1,  /* Name known, key matches, NOT manually verified */
    TOFU_KEY_MATCH_VERIFIED = 2, /* Name known, key matches, manually verified */
    TOFU_KEY_CONFLICT      = 3   /* Name known, public key DOES NOT match (warning!) */
} tofu_result_t;

/**
 * Generate a new Ed25519 keypair and write to file.
 * Creates parent directory (~/.fear/) if needed.
 * File format: two lines, "PK:<base64url>" and "SK:<base64url>".
 * File permissions set to 0600 on POSIX.
 *
 * @param path  Output file path (e.g. ~/.fear/identity)
 * @return 0 on success, -1 on error
 */
int identity_generate(const char *path);

/**
 * Load Ed25519 keypair from file.
 *
 * @param path  Identity file path
 * @param pk    Output: 32-byte public key
 * @param sk    Output: 64-byte secret key
 * @return 0 on success, -1 if file missing/corrupt
 */
int identity_load(const char *path, uint8_t *pk, uint8_t *sk);

/**
 * Load only the public key from identity file (first line).
 *
 * @param path  Identity file path
 * @param pk    Output: 32-byte public key
 * @return 0 on success, -1 if file missing/corrupt
 */
int identity_load_pk(const char *path, uint8_t *pk);

/**
 * Create a detached Ed25519 signature.
 *
 * @param msg      Message to sign
 * @param msg_len  Message length
 * @param sk       64-byte secret key
 * @param sig_out  Output: 64-byte signature
 * @return 0 on success
 */
int identity_sign(const uint8_t *msg, size_t msg_len,
                  const uint8_t sk[IDENTITY_SK_BYTES],
                  uint8_t sig_out[IDENTITY_SIG_BYTES]);

/**
 * Verify a detached Ed25519 signature.
 *
 * @param msg      Message that was signed
 * @param msg_len  Message length
 * @param sig      64-byte signature
 * @param pk       32-byte public key
 * @return 0 if valid, -1 if invalid
 */
int identity_verify(const uint8_t *msg, size_t msg_len,
                    const uint8_t sig[IDENTITY_SIG_BYTES],
                    const uint8_t pk[IDENTITY_PK_BYTES]);

/**
 * TOFU (Trust On First Use) check against known-keys database.
 *
 * Database format: one line per entry, "<name>\t<base64url(pk)>\n".
 * On TOFU_NEW_KEY, the entry is appended to the database file.
 *
 * @param db_path  Path to known_keys file (e.g. ~/.fear/known_keys)
 * @param name     Peer display name
 * @param pk       32-byte Ed25519 public key of peer
 * @return TOFU_NEW_KEY, TOFU_KEY_MATCH, or TOFU_KEY_CONFLICT
 */
tofu_result_t identity_tofu_check(const char *db_path,
                                  const char *name,
                                  const uint8_t pk[IDENTITY_PK_BYTES]);

/**
 * Get default identity file path.
 * POSIX: ~/.fear/identity
 * Windows: %APPDATA%\fear\identity
 *
 * @param buf      Output buffer
 * @param bufsize  Buffer size
 * @return 0 on success, -1 on error
 */
int identity_default_path(char *buf, size_t bufsize);

/**
 * Get default known-keys database path.
 * POSIX: ~/.fear/known_keys
 * Windows: %APPDATA%\fear\known_keys
 *
 * @param buf      Output buffer
 * @param bufsize  Buffer size
 * @return 0 on success, -1 on error
 */
int identity_default_known_keys_path(char *buf, size_t bufsize);

/**
 * Compute human-readable fingerprint of a public key.
 * Format: "ab:cd:ef:01:23:45:67:89" (first 8 bytes of BLAKE2b hash).
 *
 * @param pk   32-byte public key
 * @param out  Output buffer (at least IDENTITY_FINGERPRINT_LEN bytes)
 * @return Pointer to out
 */
char *identity_pk_fingerprint(const uint8_t pk[IDENTITY_PK_BYTES],
                              char out[IDENTITY_FINGERPRINT_LEN]);

/**
 * Mark a known key as manually verified.
 *
 * @param db_path  Path to known_keys file
 * @param name     Peer display name
 * @return 0 on success, -1 if name not found or error
 */
int identity_mark_verified(const char *db_path, const char *name);

/**
 * Remove a key entry from the known-keys database.
 *
 * @param db_path  Path to known_keys file
 * @param name     Peer display name to remove
 * @return 0 on success, -1 if name not found or error
 */
int identity_remove_key(const char *db_path, const char *name);

/**
 * Import a public key into the known-keys database.
 * If name already exists, replaces the key (resets verified to 0).
 *
 * @param db_path  Path to known_keys file
 * @param name     Peer display name
 * @param pk       32-byte Ed25519 public key
 * @param verified 1 to mark as verified, 0 for TOFU-trusted
 * @return 0 on success, -1 on error
 */
int identity_import_key(const char *db_path, const char *name,
                        const uint8_t pk[IDENTITY_PK_BYTES], int verified);

/**
 * Callback type for identity_list_keys.
 * @param name       Peer display name
 * @param pk_b64     Base64url-encoded public key
 * @param verified   1 if manually verified, 0 otherwise
 * @param ctx        User context pointer
 */
typedef void (*identity_key_callback_t)(const char *name, const char *pk_b64,
                                        int verified, void *ctx);

/**
 * List all entries in the known-keys database.
 *
 * @param db_path   Path to known_keys file
 * @param callback  Called for each entry
 * @param ctx       User context passed to callback
 * @return Number of entries, or -1 on error
 */
int identity_list_keys(const char *db_path, identity_key_callback_t callback,
                       void *ctx);

#endif /* FEAR_IDENTITY_H */
