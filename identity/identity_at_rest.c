/**
 * @file identity_at_rest.c
 * @brief See identity_at_rest.h.
 *
 * The keyring holds a wrapping key, not the identity itself. Putting the
 * Ed25519 secret key straight into the keyring would be less code, but the
 * identity would stop being a file the user can copy, back up or move to
 * another machine - and that file is how people already move their identity
 * around. So the file stays the identity, and the keyring makes it useless
 * on its own.
 */
#include "identity_at_rest.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#ifdef FEAR_HAVE_LIBSECRET
#include <libsecret/secret.h>

/* One entry, so the attribute exists only to name it. */
static const SecretSchema *fear_schema(void) {
    static const SecretSchema s = {
        "ru.fear.IdentityKey", SECRET_SCHEMA_NONE,
        {
            { "slot", SECRET_SCHEMA_ATTRIBUTE_STRING },
            { NULL, 0 },
        },
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    return &s;
}

#define IAR_SLOT "identity-file-key"
#define IAR_LABEL "F.E.A.R. identity key"

/**
 * The wrapping key from the keyring, creating it the first time.
 *
 * @param create whether a missing key should be made. Reading must not
 *               create one: a file written under a key that has since been
 *               deleted would otherwise silently get a fresh key and fail to
 *               open, which reads as corruption rather than as what it is.
 */
static int secret_key_get(uint8_t key[crypto_secretbox_KEYBYTES], int create) {
    GError *err = NULL;
    gchar *b64 = secret_password_lookup_sync(fear_schema(), NULL, &err,
                                             "slot", IAR_SLOT, NULL);
    if (err) {                       /* no keyring running, or it is locked */
        g_error_free(err);
        return -1;
    }

    if (b64) {
        size_t bin_len = 0;
        int ok = (sodium_base642bin(key, crypto_secretbox_KEYBYTES,
                                    b64, strlen(b64), NULL, &bin_len, NULL,
                                    sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0 &&
                  bin_len == crypto_secretbox_KEYBYTES);
        secret_password_free(b64);
        return ok ? 0 : -1;
    }

    if (!create) return -1;

    randombytes_buf(key, crypto_secretbox_KEYBYTES);
    char enc[128];
    if (sodium_bin2base64(enc, sizeof enc, key, crypto_secretbox_KEYBYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        sodium_memzero(key, crypto_secretbox_KEYBYTES);
        return -1;
    }

    gboolean stored = secret_password_store_sync(
        fear_schema(), SECRET_COLLECTION_DEFAULT, IAR_LABEL, enc,
        NULL, &err, "slot", IAR_SLOT, NULL);
    sodium_memzero(enc, sizeof enc);

    if (err) { g_error_free(err); stored = FALSE; }
    if (!stored) {
        sodium_memzero(key, crypto_secretbox_KEYBYTES);
        return -1;
    }
    return 0;
}
#endif /* FEAR_HAVE_LIBSECRET */

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

const char *iar_mode_name(iar_mode_t mode) {
    switch (mode) {
        case IAR_SECRET_SERVICE: return "secret-service";
        case IAR_DPAPI:          return "dpapi";
        case IAR_NONE:           break;
    }
    return "none";
}

iar_mode_t iar_mode_from_name(const char *name) {
    if (!name) return IAR_NONE;
    if (strcmp(name, "secret-service") == 0) return IAR_SECRET_SERVICE;
    if (strcmp(name, "dpapi") == 0)          return IAR_DPAPI;
    return IAR_NONE;
}

iar_mode_t iar_available(void) {
#if defined(_WIN32)
    return IAR_DPAPI;
#elif defined(FEAR_HAVE_LIBSECRET)
    /* Ask the service something harmless. A missing entry is fine; an error
     * means there is nothing to ask. */
    GError *err = NULL;
    gchar *b64 = secret_password_lookup_sync(fear_schema(), NULL, &err,
                                             "slot", IAR_SLOT, NULL);
    if (err) { g_error_free(err); return IAR_NONE; }
    if (b64) secret_password_free(b64);
    return IAR_SECRET_SERVICE;
#else
    return IAR_NONE;
#endif
}

iar_mode_t iar_protect(const uint8_t *plain, size_t plen,
                       uint8_t **out, size_t *out_len) {
    if (!plain || !out || !out_len || plen == 0) return IAR_NONE;
    *out = NULL;
    *out_len = 0;

#if defined(_WIN32)
    DATA_BLOB in, blob;
    in.pbData = (BYTE *)plain;
    in.cbData = (DWORD)plen;
    if (!CryptProtectData(&in, L"F.E.A.R. identity", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &blob)) {
        return IAR_NONE;
    }
    uint8_t *buf = (uint8_t *)malloc(blob.cbData);
    if (!buf) { LocalFree(blob.pbData); return IAR_NONE; }
    memcpy(buf, blob.pbData, blob.cbData);
    *out = buf;
    *out_len = blob.cbData;
    LocalFree(blob.pbData);
    return IAR_DPAPI;

#elif defined(FEAR_HAVE_LIBSECRET)
    uint8_t key[crypto_secretbox_KEYBYTES];
    if (secret_key_get(key, 1) != 0) return IAR_NONE;

    size_t blen = crypto_secretbox_NONCEBYTES + plen + crypto_secretbox_MACBYTES;
    uint8_t *buf = (uint8_t *)malloc(blen);
    if (!buf) { sodium_memzero(key, sizeof key); return IAR_NONE; }

    randombytes_buf(buf, crypto_secretbox_NONCEBYTES);
    int rc = crypto_secretbox_easy(buf + crypto_secretbox_NONCEBYTES,
                                   plain, plen, buf, key);
    sodium_memzero(key, sizeof key);
    if (rc != 0) { free(buf); return IAR_NONE; }

    *out = buf;
    *out_len = blen;
    return IAR_SECRET_SERVICE;

#else
    (void)plain; (void)plen;
    return IAR_NONE;
#endif
}

int iar_unprotect(iar_mode_t mode, const uint8_t *blob, size_t blen,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!blob || !out || !out_len || blen == 0) return -1;

    if (mode == IAR_DPAPI) {
#if defined(_WIN32)
        DATA_BLOB in, plain;
        in.pbData = (BYTE *)blob;
        in.cbData = (DWORD)blen;
        if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                                CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
            return -1;
        }
        int ok = (plain.cbData <= out_cap);
        if (ok) {
            memcpy(out, plain.pbData, plain.cbData);
            *out_len = plain.cbData;
        }
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
        return ok ? 0 : -1;
#else
        return -1;   /* written on Windows, opened somewhere else */
#endif
    }

    if (mode == IAR_SECRET_SERVICE) {
#if defined(FEAR_HAVE_LIBSECRET)
        if (blen < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) return -1;
        size_t plen = blen - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
        if (plen > out_cap) return -1;

        uint8_t key[crypto_secretbox_KEYBYTES];
        if (secret_key_get(key, 0) != 0) return -1;

        int rc = crypto_secretbox_open_easy(out,
                                            blob + crypto_secretbox_NONCEBYTES,
                                            blen - crypto_secretbox_NONCEBYTES,
                                            blob, key);
        sodium_memzero(key, sizeof key);
        if (rc != 0) return -1;
        *out_len = plen;
        return 0;
#else
        return -1;   /* written where a keyring was, opened where there is none */
#endif
    }

    return -1;
}
