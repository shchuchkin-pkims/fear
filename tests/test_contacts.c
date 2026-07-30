/**
 * Unit tests: contacts blob cipher (K_contacts derivation + FCN1 blob).
 */
#include "contacts_cipher.h"
#include "test_util.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    CHECK(crypto_sign_keypair(pk, sk) == 0);

    /* --- key derivation --------------------------------------------------- */
    uint8_t k1[CONTACTS_CIPHER_KEY_BYTES], k2[CONTACTS_CIPHER_KEY_BYTES];
    CHECK(contacts_cipher_derive_key(sk, k1) == 0);
    CHECK(contacts_cipher_derive_key(sk, k2) == 0);
    /* Same identity => same K_contacts (this is what makes multi-device
     * contact sync work at all). */
    CHECK(memcmp(k1, k2, sizeof k1) == 0);

    uint8_t pk_b[crypto_sign_PUBLICKEYBYTES], sk_b[crypto_sign_SECRETKEYBYTES];
    CHECK(crypto_sign_keypair(pk_b, sk_b) == 0);
    uint8_t k_other[CONTACTS_CIPHER_KEY_BYTES];
    CHECK(contacts_cipher_derive_key(sk_b, k_other) == 0);
    CHECK(memcmp(k1, k_other, sizeof k1) != 0);

    /* --- encrypt / decrypt roundtrip -------------------------------------- */
    const char *json = "{\"contacts\":[{\"name\":\"alice\",\"handle\":\"@alice\"}]}";
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    CHECK(contacts_cipher_encrypt(json, strlen(json), k1, &blob, &blob_len) == 0);
    CHECK(blob != NULL && blob_len > strlen(json));

    char *out = NULL;
    CHECK(contacts_cipher_decrypt(blob, blob_len, k1, &out) == 0);
    CHECK(out != NULL && strcmp(out, json) == 0);
    free(out);
    out = NULL;

    /* --- wrong key must fail ----------------------------------------------- */
    CHECK(contacts_cipher_decrypt(blob, blob_len, k_other, &out) != 0);

    /* --- corruption must fail ---------------------------------------------- */
    uint8_t *evil = malloc(blob_len);
    CHECK(evil != NULL);

    memcpy(evil, blob, blob_len);
    evil[0] ^= 0xFF; /* magic */
    CHECK(contacts_cipher_decrypt(evil, blob_len, k1, &out) != 0);

    memcpy(evil, blob, blob_len);
    evil[blob_len / 2] ^= 0x01;
    CHECK(contacts_cipher_decrypt(evil, blob_len, k1, &out) != 0);

    memcpy(evil, blob, blob_len);
    evil[blob_len - 1] ^= 0x01;
    CHECK(contacts_cipher_decrypt(evil, blob_len, k1, &out) != 0);

    /* truncation / garbage sizes */
    CHECK(contacts_cipher_decrypt(blob, blob_len - 1, k1, &out) != 0);
    CHECK(contacts_cipher_decrypt(blob, 0, k1, &out) != 0);
    CHECK(contacts_cipher_decrypt(blob, 4, k1, &out) != 0);

    free(evil);
    free(blob);

    /* --- empty contact list is a valid payload ----------------------------- */
    const char *empty = "{\"contacts\":[]}";
    CHECK(contacts_cipher_encrypt(empty, strlen(empty), k1, &blob, &blob_len) == 0);
    CHECK(contacts_cipher_decrypt(blob, blob_len, k1, &out) == 0);
    CHECK(strcmp(out, empty) == 0);
    free(out);
    free(blob);

    return t_report("test_contacts");
}
