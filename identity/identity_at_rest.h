/**
 * @file identity_at_rest.h
 * @brief Wrapping the Ed25519 secret key with whatever the platform keeps
 *        secrets in.
 *
 * The identity file used to hold the secret key in the clear, mode 0600.
 * That is enough against another user on the same machine and nothing else:
 * a backup, a stolen disk, or any process running as this user reads it.
 * Android has kept its copy under a Keystore-backed EncryptedFile for a
 * while; this is the desktop catching up.
 *
 * What it does not do is protect against a process running as this user
 * while the session is unlocked - the keyring is unlocked too, and it will
 * hand the key over. The threat this closes is the file leaving the machine:
 * a backup, a copied home directory, a disk pulled out of a laptop.
 *
 * The public key stays in the clear. It is public, the GUI reads it on
 * several paths that have no business unlocking a keyring, and encrypting it
 * would only mean a fingerprint could not be shown without one.
 *
 * A build without any backend, or a machine with no keyring running, keeps
 * the old plaintext form and says so once. Refusing to start would be worse:
 * headless and container use is real, and this is a hardening step, not a
 * new requirement.
 */
#ifndef FEAR_IDENTITY_AT_REST_H
#define FEAR_IDENTITY_AT_REST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which store, if any, is protecting the key on disk. */
typedef enum {
    IAR_NONE = 0,        /**< in the clear - nothing available */
    IAR_SECRET_SERVICE,  /**< libsecret / Secret Service (Linux, BSD) */
    IAR_DPAPI            /**< Windows DPAPI, user scope */
} iar_mode_t;

/**
 * The store this build and this session can actually use.
 *
 * Asked at the moment of writing rather than at build time: libsecret links
 * fine on a machine with no keyring daemon running, and the answer there is
 * IAR_NONE.
 */
iar_mode_t iar_available(void);

/**
 * Wrap a secret. Returns the mode used, or IAR_NONE if nothing could be.
 *
 * On success *out holds a malloc'd blob the caller frees.
 */
iar_mode_t iar_protect(const uint8_t *plain, size_t plen,
                       uint8_t **out, size_t *out_len);

/** Unwrap a blob written in @p mode. Returns 0 on success. */
int iar_unprotect(iar_mode_t mode, const uint8_t *blob, size_t blen,
                  uint8_t *out, size_t out_cap, size_t *out_len);

/** The name that goes in the file, and back. */
const char *iar_mode_name(iar_mode_t mode);
iar_mode_t  iar_mode_from_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_IDENTITY_AT_REST_H */
