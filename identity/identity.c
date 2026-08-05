/**
 * @file identity.c
 * @brief Ed25519 digital identity implementation for F.E.A.R. messenger
 *
 * Pure C11 + libsodium. Cross-platform (POSIX, Win32, Android NDK).
 */

#include "identity.h"
#include "identity_at_rest.h"
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
#include <fcntl.h>
#include <unistd.h>
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

/**
 * Say once that the key is on disk in the clear.
 *
 * Once, because this is a hardening step and not a new requirement: headless
 * machines and containers have no keyring, and refusing to run there would
 * be worse than the plaintext file we have had all along. Saying nothing
 * would be worse still - the difference matters to whoever is backing that
 * directory up.
 */
static void identity_warn_plaintext_once(void) {
    static int said = 0;
    if (said) return;
    said = 1;
    fprintf(stderr,
            "[identity] no secret store available - the identity key is "
            "stored unencrypted (file mode 0600 only)\n");
}

int identity_session_tag(char out[IDENTITY_SESSION_TAG_LEN]) {
    if (!out) return -1;
    uint8_t raw[16];
    randombytes_buf(raw, sizeof raw);
    return sodium_bin2base64(out, IDENTITY_SESSION_TAG_LEN,
                             raw, sizeof raw,
                             sodium_base64_VARIANT_URLSAFE_NO_PADDING)
           ? 0 : -1;
}

size_t identity_announce_signed_bytes(const char *session_tag, const char *display_name,
                                      uint8_t *out, size_t cap) {
    if (!session_tag || !display_name || !out) return 0;
    static const char ctx[] = "fear.announce.v2";
    const size_t tag_len = strlen(session_tag);
    const size_t name_len = strlen(display_name);
    const size_t total = (sizeof ctx - 1) + tag_len + name_len;
    if (total > cap) return 0;

    uint8_t *w = out;
    memcpy(w, ctx, sizeof ctx - 1); w += sizeof ctx - 1;
    memcpy(w, session_tag, tag_len); w += tag_len;
    memcpy(w, display_name, name_len);
    return total;
}

int identity_wire_room(const char *room_name, char out[IDENTITY_WIRE_ROOM_LEN]) {
    if (!room_name || !out) return -1;
    const size_t len = strlen(room_name);

    static const char ctx[] = "fear.room.v1";
    crypto_generichash_state st;
    if (crypto_generichash_init(&st, NULL, 0, 16) != 0) return -1;
    crypto_generichash_update(&st, (const uint8_t *)ctx, sizeof(ctx) - 1);
    crypto_generichash_update(&st, (const uint8_t *)room_name, len);
    uint8_t digest[16];
    if (crypto_generichash_final(&st, digest, sizeof digest) != 0) return -1;

    out[0] = 'r';
    out[1] = ':';
    return sodium_bin2base64(out + 2, IDENTITY_WIRE_ROOM_LEN - 2,
                             digest, sizeof digest,
                             sodium_base64_VARIANT_URLSAFE_NO_PADDING)
           ? 0 : -1;
}

int identity_pm_room_id_v2(const uint8_t k_pm[32],
                           char out[IDENTITY_PM_ROOM_ID_LEN]) {
    if (!k_pm || !out) return -1;

    static const char ctx[] = "fear.pm.room.v2";
    uint8_t digest[16];
    if (crypto_generichash(digest, sizeof digest,
                           (const uint8_t *)ctx, sizeof(ctx) - 1,
                           k_pm, 32) != 0) {
        return -1;
    }

    out[0] = 'p';
    out[1] = 'm';
    out[2] = ':';
    return sodium_bin2base64(out + 3, IDENTITY_PM_ROOM_ID_LEN - 3,
                             digest, sizeof digest,
                             sodium_base64_VARIANT_URLSAFE_NO_PADDING)
           ? 0 : -1;
}

/**
 * Write an identity file.
 *
 * The public key is in the clear. It is public, and several call sites read
 * it with identity_load_pk only to show a fingerprint - which has no
 * business unlocking a keyring. The secret key goes through the platform
 * store when there is one, and is written the way it always was when there
 * is not.
 */
static int identity_write_file(const char *path, const uint8_t *pk,
                               const uint8_t *sk) {
    if (ensure_parent_dir(path) != 0) return -1;

    char pk_b64[128], sk_b64[256];
    if (sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        return -1;
    }

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    iar_mode_t mode = iar_protect(sk, IDENTITY_SK_BYTES, &blob, &blob_len);

    char *enc = NULL;
    if (mode != IAR_NONE && blob) {
        size_t cap = blob_len * 4 / 3 + 8;
        enc = (char *)malloc(cap);
        if (!enc || sodium_bin2base64(enc, cap, blob, blob_len,
                                      sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
            free(enc);
            enc = NULL;
            mode = IAR_NONE;
        }
    }
    if (blob) {
        sodium_memzero(blob, blob_len);
        free(blob);
    }

    if (mode == IAR_NONE) {
        identity_warn_plaintext_once();
        if (sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, IDENTITY_SK_BYTES,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
            return -1;
        }
    }

#ifndef _WIN32
    /* Create the file with 0600 from the outset. fopen(path, "w") would create
     * it with 0666 & ~umask - typically 0644 - leaving the Ed25519 secret key
     * world-readable during the window between creation and the chmod below.
     * Still true of the wrapped form: the wrapping is not an excuse to widen
     * the permissions. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) goto fail;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); goto fail; }
#else
    FILE *f = fopen(path, "w");
    if (!f) goto fail;
#endif

    if (mode == IAR_NONE) {
        fprintf(f, "PK:%s\nSK:%s\n", pk_b64, sk_b64);
    } else {
        fprintf(f, "PK:%s\nSKENC:%s:%s\n", pk_b64, iar_mode_name(mode), enc);
    }
    fclose(f);

    /* The mode above only applies when the file is created, so still tighten
     * permissions on a pre-existing (possibly world-readable) file. */
#ifndef _WIN32
    chmod(path, 0600);
#endif

    sodium_memzero(sk_b64, sizeof(sk_b64));
    if (enc) { sodium_memzero(enc, strlen(enc)); free(enc); }
    return 0;

fail:
    sodium_memzero(sk_b64, sizeof(sk_b64));
    if (enc) { sodium_memzero(enc, strlen(enc)); free(enc); }
    return -1;
}

int identity_generate(const char *path) {
    if (sodium_init() < 0) return -1;

    uint8_t pk[IDENTITY_PK_BYTES];
    uint8_t sk[IDENTITY_SK_BYTES];
    crypto_sign_keypair(pk, sk);

    int rc = identity_write_file(path, pk, sk);
    sodium_memzero(sk, sizeof(sk));
    return rc;
}

int identity_load(const char *path, uint8_t *pk, uint8_t *sk) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    int got_pk = 0, got_sk = 0, was_plaintext = 0;

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
        } else if (strncmp(line, "SKENC:", 6) == 0) {
            /* SKENC:<mode>:<base64 blob> */
            char *rest = line + 6;
            char *colon = strchr(rest, ':');
            if (!colon) { fclose(f); return -1; }
            *colon = '\0';
            iar_mode_t mode = iar_mode_from_name(rest);
            const char *b64 = colon + 1;

            size_t blob_cap = strlen(b64);
            uint8_t *blob = (uint8_t *)malloc(blob_cap ? blob_cap : 1);
            size_t blob_len = 0;
            if (!blob ||
                sodium_base642bin(blob, blob_cap, b64, strlen(b64), NULL,
                                  &blob_len, NULL,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
                free(blob);
                fclose(f);
                return -1;
            }

            size_t got = 0;
            int rc = iar_unprotect(mode, blob, blob_len, sk,
                                   IDENTITY_SK_BYTES, &got);
            sodium_memzero(blob, blob_len);
            free(blob);
            if (rc != 0 || got != IDENTITY_SK_BYTES) {
                /* What is missing is the store, not the file. Saying which is
                 * the difference between "unlock your keyring" and "your
                 * identity is gone". */
                fprintf(stderr,
                        "[identity] the identity key is held by the %s store, "
                        "which did not open it\n", iar_mode_name(mode));
                sodium_memzero(sk, IDENTITY_SK_BYTES);
                fclose(f);
                return -1;
            }
            got_sk = 1;
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
            was_plaintext = 1;
        }
    }

    fclose(f);

    if (!got_pk || !got_sk) {
        sodium_memzero(sk, IDENTITY_SK_BYTES);
        return -1;
    }

    /* An identity written before there was a store, on a machine that has one
     * now, gets rewritten under it. A failure here is not worth stopping for:
     * the key we just read is good, and the file is no worse than it was a
     * moment ago. */
    if (was_plaintext && iar_available() != IAR_NONE) {
        (void)identity_write_file(path, pk, sk);
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

int identity_pm_room_id_v1(const uint8_t my_pk[IDENTITY_PK_BYTES],
                        const uint8_t other_pk[IDENTITY_PK_BYTES],
                        char out[IDENTITY_PM_ROOM_ID_LEN]) {
    if (!my_pk || !other_pk || !out) return -1;

    /* Лексикографический порядок — обе стороны попадают в один digest. */
    int cmp = memcmp(my_pk, other_pk, IDENTITY_PK_BYTES);
    const uint8_t *lo = (cmp <= 0) ? my_pk : other_pk;
    const uint8_t *hi = (cmp <= 0) ? other_pk : my_pk;

    uint8_t concat[IDENTITY_PK_BYTES * 2];
    memcpy(concat,                         lo, IDENTITY_PK_BYTES);
    memcpy(concat + IDENTITY_PK_BYTES,     hi, IDENTITY_PK_BYTES);

    uint8_t digest[16];
    if (crypto_generichash(digest, sizeof(digest),
                            concat, sizeof(concat), NULL, 0) != 0) {
        return -1;
    }

    /* Префикс "pm:" + 22 base64url-no-pad от 16 байт + NUL */
    out[0] = 'p';
    out[1] = 'm';
    out[2] = ':';
    if (sodium_bin2base64(out + 3, IDENTITY_PM_ROOM_ID_LEN - 3,
                          digest, sizeof(digest),
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        return -1;
    }
    return 0;
}

int identity_pm_room_key(const uint8_t my_sk[IDENTITY_SK_BYTES],
                         const uint8_t other_pk[IDENTITY_PK_BYTES],
                         uint8_t out_key[32]) {
    if (!my_sk || !other_pk || !out_key) return -1;

    /* Конвертируем ed25519 → curve25519. */
    uint8_t my_x_sk[crypto_scalarmult_curve25519_BYTES];   /* 32 */
    uint8_t their_x_pk[crypto_scalarmult_curve25519_BYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(my_x_sk, my_sk) != 0) return -1;
    if (crypto_sign_ed25519_pk_to_curve25519(their_x_pk, other_pk) != 0) {
        sodium_memzero(my_x_sk, sizeof(my_x_sk));
        return -1;
    }

    /* Plain X25519 — оба получают одинаковый shared secret. */
    uint8_t shared[crypto_scalarmult_BYTES];               /* 32 */
    int rc = crypto_scalarmult(shared, my_x_sk, their_x_pk);
    sodium_memzero(my_x_sk, sizeof(my_x_sk));
    if (rc != 0) return -1;

    /* lo/hi pk — публичный «info» с фиксированным порядком, доменно
     * разделено константой "fear.pm.v1.key". my_pk вытащим из my_sk
     * (последние 32 байта 64-байтового ed25519 sk). */
    const uint8_t *my_pk = my_sk + 32;
    int cmp = memcmp(my_pk, other_pk, IDENTITY_PK_BYTES);
    const uint8_t *lo = (cmp <= 0) ? my_pk : other_pk;
    const uint8_t *hi = (cmp <= 0) ? other_pk : my_pk;

    static const char ctx[] = "fear.pm.v1.key";
    uint8_t info[sizeof(ctx) - 1 + IDENTITY_PK_BYTES * 2];
    memcpy(info,                                       ctx,  sizeof(ctx) - 1);
    memcpy(info + (sizeof(ctx) - 1),                    lo,  IDENTITY_PK_BYTES);
    memcpy(info + (sizeof(ctx) - 1) + IDENTITY_PK_BYTES, hi, IDENTITY_PK_BYTES);

    rc = crypto_generichash(out_key, 32,
                            info, sizeof(info),
                            shared, sizeof(shared));
    sodium_memzero(shared, sizeof(shared));
    return (rc == 0) ? 0 : -1;
}

int identity_inbox_addr(const uint8_t k_pm[32],
                        uint8_t out[IDENTITY_INBOX_ADDR_BYTES]) {
    if (!k_pm || !out) return -1;
    static const char ctx[] = "fear.inbox.v1";
    return crypto_generichash(out, IDENTITY_INBOX_ADDR_BYTES,
                              (const uint8_t *)ctx, sizeof(ctx) - 1,
                              k_pm, 32) == 0 ? 0 : -1;
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
