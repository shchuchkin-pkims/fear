/**
 * @file audio_crypto.h
 * @brief AES-GCM encryption for F.E.A.R. audio calls
 *
 * Provides authenticated encryption for audio packets:
 * - AES-256-GCM encryption/decryption
 * - Automatic nonce generation
 * - Integrity verification
 */

#ifndef AUDIO_CRYPTO_H
#define AUDIO_CRYPTO_H

#include "audio_types.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Encrypt audio packet with sequence number
 *
 * Packet format: [1-byte ver][8-byte seq][encrypted opus][16-byte tag]
 *
 * @param opus Opus-encoded audio data
 * @param opus_len Length of opus data
 * @param key 32-byte encryption key
 * @param local_prefix 4-byte nonce prefix (sender-specific)
 * @param seq Sequence number for replay protection
 * @param out Output buffer (must be at least 1+8+opus_len+16 bytes)
 * @param out_len Receives actual output length
 * @return 0 on success, -1 on error
 */
int audio_encrypt_packet(const uint8_t *opus, size_t opus_len,
                         const uint8_t key[AUDIO_KEY_SIZE],
                         const uint8_t local_prefix[4],
                         uint64_t seq,
                         uint8_t *out, size_t *out_len);

/**
 * @brief Decrypt audio packet with verification
 *
 * @param pkt Encrypted packet
 * @param pkt_len Length of packet
 * @param key 32-byte decryption key
 * @param remote_prefix 4-byte nonce prefix (sender-specific)
 * @param opus_out Output buffer for decrypted opus data
 * @param opus_len Receives length of decrypted data
 * @return 0 on success, -1 on error, -2 if remote prefix not ready
 */
int audio_decrypt_packet(const uint8_t *pkt, size_t pkt_len,
                         const uint8_t key[AUDIO_KEY_SIZE],
                         const uint8_t remote_prefix[4],
                         uint8_t *opus_out, size_t *opus_len);

/**
 * @brief Generic encrypt (simplified API with random nonce)
 *
 * Output format: [12-byte nonce][encrypted data][16-byte auth tag]
 *
 * @param plaintext Input data to encrypt
 * @param plaintext_len Length of plaintext
 * @param key 32-byte encryption key
 * @param ciphertext Output buffer (must be plaintext_len + 28 bytes)
 * @param ciphertext_len Receives actual ciphertext length
 * @return 0 on success, -1 on error
 */
int audio_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                  const uint8_t key[AUDIO_KEY_SIZE],
                  uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * @brief Generic decrypt (simplified API)
 *
 * @param ciphertext Input data (with nonce and tag)
 * @param ciphertext_len Length of ciphertext
 * @param key 32-byte decryption key
 * @param plaintext Output buffer (at least ciphertext_len - 28 bytes)
 * @param plaintext_len Receives actual plaintext length
 * @return 0 on success, -1 on authentication failure
 */
int audio_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t key[AUDIO_KEY_SIZE],
                  uint8_t *plaintext, size_t *plaintext_len);

/**
 * @brief Convert hexadecimal string to binary key
 * @param hex 64-character hex string
 * @param out Output buffer (must be AUDIO_KEY_SIZE bytes)
 * @param out_len Size of output buffer
 * @return 0 on success, -1 on invalid format
 */
int hex2bytes(const char *hex, uint8_t *out, size_t out_len);

#endif /* AUDIO_CRYPTO_H */
