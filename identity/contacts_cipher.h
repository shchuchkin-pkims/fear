/**
 * @file contacts_cipher.h
 * @brief Encrypt/decrypt the contacts blob — desktop counterpart of
 *        Android com.fear.data.ContactsCipher (Phase B-3, §3).
 *
 * Wire format ('FCN1'):
 *   [4 ] magic "FCN1"
 *   [1 ] version (0x01)
 *   [1 ] reserved
 *   [24] crypto_secretbox nonce (XSalsa20)
 *   [N ] ciphertext (XSalsa20-Poly1305, plaintext = compact JSON)
 *
 * KDF (matches Android byte-for-byte):
 *   K_contacts = BLAKE2b(input="fear.contacts.v1", key=identity_sk, length=32)
 */
#ifndef FEAR_CONTACTS_CIPHER_H
#define FEAR_CONTACTS_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONTACTS_CIPHER_KDF_CTX  "fear.contacts.v1"
#define CONTACTS_CIPHER_BLOB_TYPE "contacts.v1"
#define CONTACTS_CIPHER_KEY_BYTES 32

/**
 * Derive K_contacts from identity_sk into a 32-byte buffer.
 * @return 0 on success.
 */
int contacts_cipher_derive_key(const uint8_t sk[64], uint8_t key[32]);

/**
 * Decrypt an FCN1 blob into a NUL-terminated JSON string. Caller frees.
 * @param blob       Server-fetched bytes
 * @param blob_len   Length of `blob`
 * @param key        K_contacts (32 bytes)
 * @param json_out   On success, *json_out is a malloc'd UTF-8 string.
 * @return 0 on success, -1 on bad magic / version / decrypt failure.
 */
int contacts_cipher_decrypt(const uint8_t *blob, size_t blob_len,
                            const uint8_t key[32],
                            char **json_out);

/**
 * Encrypt a JSON string into an FCN1 blob. Caller frees `*blob_out`.
 * @return 0 on success.
 */
int contacts_cipher_encrypt(const char *json, size_t json_len,
                            const uint8_t key[32],
                            uint8_t **blob_out, size_t *blob_len_out);

#ifdef __cplusplus
}
#endif

#endif
