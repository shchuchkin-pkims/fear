/**
 * @file identity.c
 * @brief Ed25519 digital identity implementation for F.E.A.R. messenger
 *
 * Pure C11 + libsodium. Cross-platform (POSIX, Win32, Android NDK).
 */

#include "identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define mkdir_p(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define mkdir_p(p) mkdir(p, 0700)
#endif

/* ===== Internal helpers ===== */

/**
 * Ensure parent directory of `path` exists.
 * Creates it with mode 0700 (POSIX) if needed.
 */
static int ensure_parent_dir(const char *path) {
    char dir[512];
    size_t len = strlen(path);
    if (len >= sizeof(dir)) return -1;
    memcpy(dir, path, len + 1);

    /* Find last separator */
    char *sep = NULL;
    for (size_t i = len; i > 0; i--) {
        if (dir[i - 1] == '/' || dir[i - 1] == '\\') {
            sep = &dir[i - 1];
            break;
        }
    }
    if (!sep) return 0; /* no directory component */

    *sep = '\0';
    if (strlen(dir) == 0) return 0;

    /* Try creating (ignore EEXIST) */
    if (mkdir_p(dir) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/**
 * Get the base directory for fear config files.
 * POSIX: ~/.fear
 * Windows: %APPDATA%\fear
 */
static int get_fear_dir(char *buf, size_t bufsize) {
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (!appdata) appdata = getenv("USERPROFILE");
    if (!appdata) return -1;
    int n = snprintf(buf, bufsize, "%s\\fear", appdata);
#else
    const char *home = getenv("HOME");
    if (!home) return -1;
    int n = snprintf(buf, bufsize, "%s/.fear", home);
#endif
    if (n < 0 || (size_t)n >= bufsize) return -1;
    return 0;
}

/* ===== Public API ===== */

int identity_generate(const char *path) {
    if (sodium_init() < 0) return -1;

    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];
    crypto_sign_keypair(pk, sk);

    if (ensure_parent_dir(path) != 0) {
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }

    /* Encode to base64url no-padding */
    char pk_b64[128], sk_b64[256];
    if (sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }
    if (sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, IDENTITY_SK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        sodium_memzero(sk, sizeof(sk));
        sodium_memzero(sk_b64, sizeof(sk_b64));
        return -1;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        sodium_memzero(sk, sizeof(sk));
        sodium_memzero(sk_b64, sizeof(sk_b64));
        return -1;
    }

    fprintf(f, "PK:%s\nSK:%s\n", pk_b64, sk_b64);
    fclose(f);

    /* Set file permissions to 0600 on POSIX */
#ifndef _WIN32
    chmod(path, 0600);
#endif

    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(sk_b64, sizeof(sk_b64));
    return 0;
}

int identity_load(const char *path, uint8_t *pk, uint8_t *sk) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    int got_pk = 0, got_sk = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Remove trailing whitespace */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' ')) {
            line[--len] = '\0';
        }

        if (strncmp(line, "PK:", 3) == 0) {
            const char *b64 = line + 3;
            size_t bin_len = 0;
            if (sodium_base642bin(pk, IDENTITY_PK_BYTES, b64, strlen(b64),
                                  NULL, &bin_len, NULL,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
                bin_len != IDENTITY_PK_BYTES) {
                fclose(f);
                return -1;
            }
            got_pk = 1;
        } else if (strncmp(line, "SK:", 3) == 0) {
            const char *b64 = line + 3;
            size_t bin_len = 0;
            if (sodium_base642bin(sk, IDENTITY_SK_BYTES, b64, strlen(b64),
                                  NULL, &bin_len, NULL,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
                bin_len != IDENTITY_SK_BYTES) {
                fclose(f);
                sodium_memzero(sk, IDENTITY_SK_BYTES);
                return -1;
            }
            got_sk = 1;
        }
    }

    fclose(f);

    if (!got_pk || !got_sk) {
        sodium_memzero(sk, IDENTITY_SK_BYTES);
        return -1;
    }

    return 0;
}

int identity_load_pk(const char *path, uint8_t *pk) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' ')) {
            line[--len] = '\0';
        }

        if (strncmp(line, "PK:", 3) == 0) {
            const char *b64 = line + 3;
            size_t bin_len = 0;
            if (sodium_base642bin(pk, IDENTITY_PK_BYTES, b64, strlen(b64),
                                  NULL, &bin_len, NULL,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
                bin_len != IDENTITY_PK_BYTES) {
                fclose(f);
                return -1;
            }
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

int identity_sign(const uint8_t *msg, size_t msg_len,
                  const uint8_t sk[IDENTITY_SK_BYTES],
                  uint8_t sig_out[IDENTITY_SIG_BYTES]) {
    return crypto_sign_detached(sig_out, NULL, msg, msg_len, sk);
}

int identity_verify(const uint8_t *msg, size_t msg_len,
                    const uint8_t sig[IDENTITY_SIG_BYTES],
                    const uint8_t pk[IDENTITY_PK_BYTES]) {
    return crypto_sign_verify_detached(sig, msg, msg_len, pk);
}

tofu_result_t identity_tofu_check(const char *db_path,
                                  const char *name,
                                  const uint8_t pk[IDENTITY_PK_BYTES]) {
    /* Encode incoming pk to base64 for comparison */
    char pk_b64[128];
    if (sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        return TOFU_KEY_CONFLICT; /* safe fallback: treat as conflict */
    }

    size_t name_len = strlen(name);

    /* Read existing database */
    /* Format: name\tpk_b64[\tverified]\n  (verified field optional, default 0) */
    FILE *f = fopen(db_path, "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            /* Remove trailing whitespace */
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                               line[len - 1] == ' ')) {
                line[--len] = '\0';
            }
            if (len == 0) continue;

            /* Find first tab separator (name\trest) */
            char *tab1 = strchr(line, '\t');
            if (!tab1) continue;

            size_t entry_name_len = (size_t)(tab1 - line);
            const char *rest = tab1 + 1;

            /* Parse pk and optional verified flag */
            char entry_pk[256];
            int verified = 0;
            char *tab2 = strchr(rest, '\t');
            if (tab2) {
                size_t pk_len = (size_t)(tab2 - rest);
                if (pk_len >= sizeof(entry_pk)) pk_len = sizeof(entry_pk) - 1;
                memcpy(entry_pk, rest, pk_len);
                entry_pk[pk_len] = '\0';
                verified = atoi(tab2 + 1);
            } else {
                strncpy(entry_pk, rest, sizeof(entry_pk) - 1);
                entry_pk[sizeof(entry_pk) - 1] = '\0';
            }

            /* Compare name */
            if (entry_name_len == name_len &&
                memcmp(line, name, name_len) == 0) {
                fclose(f);
                /* Name found — compare keys */
                if (strcmp(entry_pk, pk_b64) == 0) {
                    return verified ? TOFU_KEY_MATCH_VERIFIED : TOFU_KEY_MATCH;
                } else {
                    return TOFU_KEY_CONFLICT;
                }
            }
        }
        fclose(f);
    }

    /* Name not found — store and trust (TOFU) */
    if (ensure_parent_dir(db_path) != 0) {
        return TOFU_NEW_KEY; /* still trust, just can't persist */
    }

    f = fopen(db_path, "a");
    if (f) {
        fprintf(f, "%s\t%s\t0\n", name, pk_b64);
        fclose(f);
    }

    return TOFU_NEW_KEY;
}

int identity_default_path(char *buf, size_t bufsize) {
    char dir[512];
    if (get_fear_dir(dir, sizeof(dir)) != 0) return -1;
#ifdef _WIN32
    int n = snprintf(buf, bufsize, "%s\\identity", dir);
#else
    int n = snprintf(buf, bufsize, "%s/identity", dir);
#endif
    if (n < 0 || (size_t)n >= bufsize) return -1;
    return 0;
}

int identity_default_known_keys_path(char *buf, size_t bufsize) {
    char dir[512];
    if (get_fear_dir(dir, sizeof(dir)) != 0) return -1;
#ifdef _WIN32
    int n = snprintf(buf, bufsize, "%s\\known_keys", dir);
#else
    int n = snprintf(buf, bufsize, "%s/known_keys", dir);
#endif
    if (n < 0 || (size_t)n >= bufsize) return -1;
    return 0;
}

char *identity_pk_fingerprint(const uint8_t pk[IDENTITY_PK_BYTES],
                              char out[IDENTITY_FINGERPRINT_LEN]) {
    /* BLAKE2b hash of public key, take first 8 bytes */
    uint8_t hash[32];
    crypto_generichash(hash, sizeof(hash), pk, IDENTITY_PK_BYTES, NULL, 0);

    /* Format as xx:xx:xx:xx:xx:xx:xx:xx */
    for (int i = 0; i < 8; i++) {
        snprintf(out + i * 3, 4, "%02x%s", hash[i], (i < 7) ? ":" : "");
    }
    out[23] = '\0';
    return out;
}

/**
 * Helper: rewrite known_keys file.
 * Reads all entries, applies transform, writes back.
 * transform returns: 0 = keep as-is, 1 = modified (write new values), -1 = delete
 */
typedef struct {
    char name[256];
    char pk_b64[256];
    int verified;
} known_key_entry_t;

static int rewrite_known_keys(const char *db_path,
                               int (*transform)(known_key_entry_t *entry, void *ctx),
                               void *ctx) {
    /* Read all entries */
    known_key_entry_t entries[1024];
    int count = 0;
    int changed = 0;

    FILE *f = fopen(db_path, "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f) && count < 1024) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                               line[len - 1] == ' ')) {
                line[--len] = '\0';
            }
            if (len == 0) continue;

            char *tab1 = strchr(line, '\t');
            if (!tab1) continue;

            known_key_entry_t *e = &entries[count];
            size_t name_len = (size_t)(tab1 - line);
            if (name_len >= sizeof(e->name)) name_len = sizeof(e->name) - 1;
            memcpy(e->name, line, name_len);
            e->name[name_len] = '\0';

            const char *rest = tab1 + 1;
            char *tab2 = strchr(rest, '\t');
            if (tab2) {
                size_t pk_len = (size_t)(tab2 - rest);
                if (pk_len >= sizeof(e->pk_b64)) pk_len = sizeof(e->pk_b64) - 1;
                memcpy(e->pk_b64, rest, pk_len);
                e->pk_b64[pk_len] = '\0';
                e->verified = atoi(tab2 + 1);
            } else {
                strncpy(e->pk_b64, rest, sizeof(e->pk_b64) - 1);
                e->pk_b64[sizeof(e->pk_b64) - 1] = '\0';
                e->verified = 0;
            }
            count++;
        }
        fclose(f);
    }

    /* Apply transform */
    int new_count = 0;
    known_key_entry_t result[1024];
    for (int i = 0; i < count; i++) {
        int rc = transform(&entries[i], ctx);
        if (rc == -1) {
            changed = 1; /* deleted */
            continue;
        }
        if (rc == 1) changed = 1; /* modified */
        result[new_count++] = entries[i];
    }

    if (!changed) return -1; /* nothing changed = name not found */

    /* Write back */
    f = fopen(db_path, "w");
    if (!f) return -1;
    for (int i = 0; i < new_count; i++) {
        fprintf(f, "%s\t%s\t%d\n", result[i].name, result[i].pk_b64, result[i].verified);
    }
    fclose(f);
    return 0;
}

static int transform_mark_verified(known_key_entry_t *entry, void *ctx) {
    const char *name = (const char *)ctx;
    if (strcmp(entry->name, name) == 0) {
        entry->verified = 1;
        return 1;
    }
    return 0;
}

int identity_mark_verified(const char *db_path, const char *name) {
    return rewrite_known_keys(db_path, transform_mark_verified, (void *)name);
}

static int transform_remove(known_key_entry_t *entry, void *ctx) {
    const char *name = (const char *)ctx;
    if (strcmp(entry->name, name) == 0) return -1; /* delete */
    return 0;
}

int identity_remove_key(const char *db_path, const char *name) {
    return rewrite_known_keys(db_path, transform_remove, (void *)name);
}

int identity_import_key(const char *db_path, const char *name,
                        const uint8_t pk[IDENTITY_PK_BYTES], int verified) {
    char pk_b64[128];
    if (sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        return -1;
    }

    /* First remove existing entry for this name (if any) */
    identity_remove_key(db_path, name);

    /* Append new entry */
    if (ensure_parent_dir(db_path) != 0) return -1;

    FILE *f = fopen(db_path, "a");
    if (!f) return -1;
    fprintf(f, "%s\t%s\t%d\n", name, pk_b64, verified ? 1 : 0);
    fclose(f);
    return 0;
}

int identity_list_keys(const char *db_path, identity_key_callback_t callback,
                       void *ctx) {
    FILE *f = fopen(db_path, "r");
    if (!f) return -1;

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' ')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        char *tab1 = strchr(line, '\t');
        if (!tab1) continue;

        *tab1 = '\0';
        const char *name = line;
        const char *rest = tab1 + 1;

        char pk_b64[256];
        int verified = 0;
        char *tab2 = strchr(rest, '\t');
        if (tab2) {
            size_t pk_len = (size_t)(tab2 - rest);
            if (pk_len >= sizeof(pk_b64)) pk_len = sizeof(pk_b64) - 1;
            memcpy(pk_b64, rest, pk_len);
            pk_b64[pk_len] = '\0';
            verified = atoi(tab2 + 1);
        } else {
            strncpy(pk_b64, rest, sizeof(pk_b64) - 1);
            pk_b64[sizeof(pk_b64) - 1] = '\0';
        }

        if (callback) callback(name, pk_b64, verified, ctx);
        count++;
    }

    fclose(f);
    return count;
}
