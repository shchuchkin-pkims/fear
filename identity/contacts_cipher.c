#include "contacts_cipher.h"

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#define MAGIC      "FCN1"
#define VERSION    0x01
#define HEADER_LEN (4 + 1 + 1 + crypto_secretbox_NONCEBYTES)   /* 30 */

int contacts_cipher_derive_key(const uint8_t sk[64], uint8_t key[32]) {
    if (!sk || !key) return -1;
    static const char ctx[] = CONTACTS_CIPHER_KDF_CTX;
    /* BLAKE2b(input=ctx, key=sk, length=32) — same as Android. */
    if (crypto_generichash(key, 32,
                            (const unsigned char *)ctx, sizeof(ctx) - 1,
                            sk, 64) != 0) {
        return -1;
    }
    return 0;
}

int contacts_cipher_decrypt(const uint8_t *blob, size_t blob_len,
                            const uint8_t key[32],
                            char **json_out) {
    if (!blob || !key || !json_out) return -1;
    if (blob_len < HEADER_LEN + crypto_secretbox_MACBYTES) return -1;
    if (memcmp(blob, MAGIC, 4) != 0) return -1;
    if (blob[4] != VERSION) return -1;

    const uint8_t *nonce  = blob + 6;
    const uint8_t *cipher = blob + HEADER_LEN;
    size_t cipher_len     = blob_len - HEADER_LEN;

    size_t plaintext_len = cipher_len - crypto_secretbox_MACBYTES;
    char *out = (char *)malloc(plaintext_len + 1);
    if (!out) return -1;
    if (crypto_secretbox_open_easy((unsigned char *)out, cipher, cipher_len,
                                    nonce, key) != 0) {
        free(out);
        return -1;
    }
    out[plaintext_len] = '\0';
    *json_out = out;
    return 0;
}

int contacts_cipher_encrypt(const char *json, size_t json_len,
                            const uint8_t key[32],
                            uint8_t **blob_out, size_t *blob_len_out) {
    if (!json || !key || !blob_out || !blob_len_out) return -1;
    if (sodium_init() < 0) return -1;

    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t cipher_len = json_len + crypto_secretbox_MACBYTES;
    size_t total = HEADER_LEN + cipher_len;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) return -1;

    memcpy(out, MAGIC, 4);
    out[4] = VERSION;
    out[5] = 0x00;
    memcpy(out + 6, nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(out + HEADER_LEN,
                               (const unsigned char *)json, json_len,
                               nonce, key) != 0) {
        free(out);
        return -1;
    }

    *blob_out = out;
    *blob_len_out = total;
    return 0;
}
