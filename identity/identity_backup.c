/**
 * @file identity_backup.c
 * @brief Encrypted identity backup (.fbk) — implementation
 *
 * See identity_backup.h for wire format and parameter tuning.
 */

#include "identity_backup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ===== Endian helpers (host → big-endian uint64) ===== */

static void u64_to_be(uint8_t out[8], uint64_t v) {
    for (int i = 7; i >= 0; --i) { out[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

static uint64_t be_to_u64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) { v = (v << 8) | in[i]; }
    return v;
}

/* ===== Plaintext JSON (compact, hand-built — no JSON lib dependency) ===== */

/**
 * Build:  {"v":1,"sk":"<b64>","pk":"<b64>","ts":<unix>}
 * Returns 0 on success, -1 if buffer too small.
 */
static int build_plaintext_json(char *out, size_t cap,
                                const uint8_t sk[IDENTITY_SK_BYTES],
                                const uint8_t pk[IDENTITY_PK_BYTES],
                                int64_t ts) {
    char sk_b64[256], pk_b64[128];
    if (sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, IDENTITY_SK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        return -1;
    }
    if (sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, IDENTITY_PK_BYTES,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        sodium_memzero(sk_b64, sizeof(sk_b64));
        return -1;
    }
    int n = snprintf(out, cap,
                     "{\"v\":1,\"sk\":\"%s\",\"pk\":\"%s\",\"ts\":%lld}",
                     sk_b64, pk_b64, (long long)ts);
    sodium_memzero(sk_b64, sizeof(sk_b64));
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

/**
 * Extract a base64url field from compact JSON like {"key":"value"...}.
 * Returns 0 on success, -1 if field absent or malformed.
 */
static int json_extract_b64(const char *json, const char *key,
                            uint8_t *out, size_t out_len) {
    char needle[32];
    int n = snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return -1;
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += n;
    const char *end = strchr(p, '"');
    if (!end) return -1;

    size_t bin_len = 0;
    if (sodium_base642bin(out, out_len, p, (size_t)(end - p),
                          NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
        bin_len != out_len) {
        return -1;
    }
    return 0;
}

/* ===== Buffer-form export/import (the workhorse) ===== */

int identity_backup_export_buf(uint8_t **out_buf, size_t *out_len,
                               const uint8_t sk[IDENTITY_SK_BYTES],
                               const uint8_t pk[IDENTITY_PK_BYTES],
                               const char *password) {
    if (!out_buf || !out_len || !sk || !pk || !password) return -1;
    if (sodium_init() < 0) return -1;

    /* 1) Build plaintext JSON */
    char plaintext[512];
    if (build_plaintext_json(plaintext, sizeof(plaintext),
                             sk, pk, (int64_t)time(NULL)) != 0) {
        return -1;
    }
    size_t plaintext_len = strlen(plaintext);

    /* 2) Derive key from password via argon2id */
    uint8_t salt[crypto_pwhash_SALTBYTES];      /* 16 */
    randombytes_buf(salt, sizeof(salt));

    uint8_t key[crypto_secretbox_KEYBYTES];     /* 32 */
    if (crypto_pwhash(key, sizeof(key),
                      password, strlen(password),
                      salt,
                      IDENTITY_BACKUP_OPSLIMIT,
                      (size_t)IDENTITY_BACKUP_MEMLIMIT,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(plaintext, sizeof(plaintext));
        return -1;
    }

    /* 3) Encrypt with XSalsa20-Poly1305 */
    uint8_t nonce[crypto_secretbox_NONCEBYTES]; /* 24 */
    randombytes_buf(nonce, sizeof(nonce));

    size_t cipher_len = plaintext_len + crypto_secretbox_MACBYTES;
    size_t total = (size_t)IDENTITY_BACKUP_HEADER_LEN + cipher_len;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        sodium_memzero(key, sizeof(key));
        sodium_memzero(plaintext, sizeof(plaintext));
        return -1;
    }

    /* Header */
    memcpy(buf, IDENTITY_BACKUP_MAGIC, 4);
    buf[4] = IDENTITY_BACKUP_VERSION;
    buf[5] = 0x00;                                  /* reserved */
    memcpy(buf + 6, salt, 16);
    u64_to_be(buf + 22, IDENTITY_BACKUP_OPSLIMIT);
    u64_to_be(buf + 30, IDENTITY_BACKUP_MEMLIMIT);
    memcpy(buf + 38, nonce, 24);

    /* Ciphertext appended */
    if (crypto_secretbox_easy(buf + IDENTITY_BACKUP_HEADER_LEN,
                              (const uint8_t *)plaintext, plaintext_len,
                              nonce, key) != 0) {
        sodium_memzero(buf, total);
        free(buf);
        sodium_memzero(key, sizeof(key));
        sodium_memzero(plaintext, sizeof(plaintext));
        return -1;
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(plaintext, sizeof(plaintext));

    *out_buf = buf;
    *out_len = total;
    return 0;
}

int identity_backup_import_buf(const uint8_t *buf, size_t buf_len,
                               const char *password,
                               uint8_t sk_out[IDENTITY_SK_BYTES],
                               uint8_t pk_out[IDENTITY_PK_BYTES]) {
    if (!buf || !password || !sk_out || !pk_out) return -1;
    if (buf_len < (size_t)IDENTITY_BACKUP_HEADER_LEN + crypto_secretbox_MACBYTES) return -1;
    if (sodium_init() < 0) return -1;

    /* Validate header */
    if (memcmp(buf, IDENTITY_BACKUP_MAGIC, 4) != 0) return -1;
    if (buf[4] != IDENTITY_BACKUP_VERSION) return -1;

    const uint8_t *salt   = buf + 6;
    uint64_t opslimit     = be_to_u64(buf + 22);
    uint64_t memlimit     = be_to_u64(buf + 30);
    const uint8_t *nonce  = buf + 38;
    const uint8_t *cipher = buf + IDENTITY_BACKUP_HEADER_LEN;
    size_t cipher_len     = buf_len - IDENTITY_BACKUP_HEADER_LEN;

    /* Sanity-cap KDF parameters: malicious file could specify gigantic memlimit
     * to OOM us. Cap at 1 GB / 10 ops. Legitimate v1 files use 64 MB / 3 ops. */
    if (memlimit > (1024ULL * 1024 * 1024) || opslimit > 10) return -1;

    /* Derive key */
    uint8_t key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(key, sizeof(key),
                      password, strlen(password),
                      salt, opslimit, (size_t)memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1;
    }

    /* Decrypt */
    size_t plaintext_len = cipher_len - crypto_secretbox_MACBYTES;
    uint8_t *plaintext = (uint8_t *)malloc(plaintext_len + 1);
    if (!plaintext) {
        sodium_memzero(key, sizeof(key));
        return -1;
    }
    if (crypto_secretbox_open_easy(plaintext, cipher, cipher_len,
                                   nonce, key) != 0) {
        sodium_memzero(key, sizeof(key));
        free(plaintext);
        return -1;  /* bad password or corruption */
    }
    sodium_memzero(key, sizeof(key));
    plaintext[plaintext_len] = '\0';

    /* Parse JSON, pull sk and pk */
    int rc = -1;
    do {
        if (json_extract_b64((const char *)plaintext, "sk", sk_out, IDENTITY_SK_BYTES) != 0) break;
        if (json_extract_b64((const char *)plaintext, "pk", pk_out, IDENTITY_PK_BYTES) != 0) break;
        rc = 0;
    } while (0);

    sodium_memzero(plaintext, plaintext_len);
    free(plaintext);
    if (rc != 0) sodium_memzero(sk_out, IDENTITY_SK_BYTES);
    return rc;
}

/* ===== File-form thin wrappers ===== */

int identity_backup_export(const char *out_path,
                           const uint8_t sk[IDENTITY_SK_BYTES],
                           const uint8_t pk[IDENTITY_PK_BYTES],
                           const char *password) {
    uint8_t *buf = NULL;
    size_t   buf_len = 0;
    if (identity_backup_export_buf(&buf, &buf_len, sk, pk, password) != 0) return -1;

    FILE *f = fopen(out_path, "wb");
    if (!f) {
        sodium_memzero(buf, buf_len);
        free(buf);
        return -1;
    }
    size_t wrote = fwrite(buf, 1, buf_len, f);
    fclose(f);
    sodium_memzero(buf, buf_len);
    free(buf);
    return (wrote == buf_len) ? 0 : -1;
}

int identity_backup_import(const char *in_path,
                           const char *password,
                           uint8_t sk_out[IDENTITY_SK_BYTES],
                           uint8_t pk_out[IDENTITY_PK_BYTES]) {
    FILE *f = fopen(in_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 64 * 1024) { fclose(f); return -1; }  /* sanity cap */

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return -1; }

    int rc = identity_backup_import_buf(buf, got, password, sk_out, pk_out);
    sodium_memzero(buf, got);
    free(buf);
    return rc;
}
