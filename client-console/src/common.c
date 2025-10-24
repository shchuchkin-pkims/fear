/**
 * @file common.c
 * @brief Common utilities for F.E.A.R. messenger
 *
 * Provides shared functionality used across client and server modules:
 * - Binary I/O helpers (little-endian integer encoding/decoding)
 * - Network send/receive with complete data transfer guarantees
 * - Base64 encoding/decoding for key representation
 * - CRC32 checksum for file integrity verification
 * - AES-256-GCM encryption/decryption wrappers
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

/**
 * @brief Read 16-bit unsigned integer from buffer (little-endian)
 * @param p Pointer to 2-byte buffer
 * @return Decoded uint16_t value
 */
uint16_t rd_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * @brief Write 16-bit unsigned integer to buffer (little-endian)
 * @param p Pointer to 2-byte buffer
 * @param v Value to encode
 */
void wr_u16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
}

/**
 * @brief Read 32-bit unsigned integer from buffer (little-endian)
 * @param p Pointer to 4-byte buffer
 * @return Decoded uint32_t value
 */
uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * @brief Write 32-bit unsigned integer to buffer (little-endian)
 * @param p Pointer to 4-byte buffer
 * @param v Value to encode
 */
void wr_u32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

/**
 * @brief Print error message and exit program
 * @param msg Error message prefix (will be passed to perror)
 * @note This function never returns
 */
void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/**
 * @brief Receive exactly len bytes from socket (blocking)
 *
 * Repeatedly calls recv() until all requested bytes are received.
 * This ensures complete message reception even if data arrives in fragments.
 *
 * @param fd Socket descriptor
 * @param buf Buffer to store received data
 * @param len Number of bytes to receive
 * @return 0 on success, -1 on error or connection closed
 *
 * @note Blocks until all data is received or error occurs
 * @note Returns -1 if connection is closed before all data arrives
 */
int recv_all(sock_t fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t*)buf;
    size_t got = 0;
    int n;

    while (got < len) {
        n = (int)recv(fd, (char*)p + got, (int)(len - got), 0);
        if (n <= 0) {
            return -1; /* Connection closed or error */
        }
        got += (size_t)n;
    }

    return 0;
}

/**
 * @brief Send exactly len bytes to socket (blocking)
 *
 * Repeatedly calls send() until all data is transmitted.
 * This ensures complete message transmission even if kernel buffers are full.
 *
 * @param fd Socket descriptor
 * @param buf Buffer containing data to send
 * @param len Number of bytes to send
 * @return 0 on success, -1 on error or connection closed
 *
 * @note Blocks until all data is sent or error occurs
 * @note Returns -1 if connection is closed before all data is sent
 */
int send_all(sock_t fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t sent = 0;
    int n;

    while (sent < len) {
        n = (int)send(fd, (const char*)p + sent, (int)(len - sent), 0);
        if (n <= 0) {
            return -1; /* Connection closed or error */
        }
        sent += (size_t)n;
    }

    return 0;
}

/**
 * @brief Encode binary data to Base64 URL-safe format
 *
 * Uses libsodium's URL-safe Base64 encoding without padding (RFC 4648).
 * This format is safe for use in URLs and command-line arguments.
 *
 * @param buf Binary data to encode
 * @param len Length of binary data
 * @return Dynamically allocated Base64 string, or NULL on allocation failure
 *
 * @note Caller must free() the returned string
 * @note Uses URL-safe alphabet: A-Za-z0-9-_ (no padding)
 */
char *b64_encode(const uint8_t *buf, size_t len) {
    size_t outlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *out = (char*)malloc(outlen);
    if (!out) {
        return NULL;
    }
    sodium_bin2base64(out, outlen, buf, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return out;
}

/**
 * @brief Decode Base64 URL-safe string to binary data
 *
 * Decodes a URL-safe Base64 string (without padding) to binary form.
 *
 * @param b64 Base64-encoded string (null-terminated)
 * @param out Buffer to store decoded binary data
 * @param outlen Size of output buffer
 * @return Number of decoded bytes, or -1 on decode error
 *
 * @note Returns -1 if Base64 string is invalid or buffer too small
 */
int b64_decode(const char *b64, uint8_t *out, size_t outlen) {
    size_t real = 0;
    if (sodium_base642bin(out, outlen, b64, strlen(b64), NULL, &real, NULL,
                         sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return -1;
    }
    return (int)real;
}

/**
 * @brief Calculate CRC32 checksum of data (ISO 3309, ITU-T V.42)
 *
 * Computes standard CRC32 using polynomial 0xEDB88320 (reversed 0x04C11DB7).
 * This is the same CRC32 used in Ethernet, ZIP, PNG, and zlib.
 *
 * @param data Pointer to data buffer
 * @param len Length of data in bytes
 * @return 32-bit CRC checksum
 *
 * @note Initial CRC is 0xFFFFFFFF, final value is bitwise NOT of computed CRC
 * @note Used for file integrity verification in file transfer
 */
uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }

    return ~crc;
}

/**
 * @brief Encrypt data using AES-256-GCM (AEAD)
 *
 * Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM.
 * Provides both confidentiality (encryption) and integrity/authenticity (MAC).
 *
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param additional_data Authenticated but not encrypted metadata (room, name)
 * @param additional_data_len Length of additional data
 * @param nonce 12-byte nonce (must be unique for each message with same key)
 * @param key 32-byte encryption key
 * @param ciphertext Output buffer (must be plaintext_len + 16 bytes)
 * @param ciphertext_len Receives actual ciphertext length (plaintext_len + 16)
 * @return 0 on success, -1 on error
 *
 * @note Ciphertext includes 16-byte authentication tag (MAC)
 * @note Nonce must NEVER be reused with the same key (use randombytes_buf)
 * @note Additional data is authenticated but sent in plaintext (metadata)
 */
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *ciphertext, unsigned long long *ciphertext_len) {
    return crypto_aead_aes256gcm_encrypt(ciphertext, ciphertext_len,
                                        plaintext, plaintext_len,
                                        additional_data, additional_data_len,
                                        NULL, nonce, key);
}

/**
 * @brief Decrypt and verify data using AES-256-GCM (AEAD)
 *
 * Decrypts AES-256-GCM ciphertext and verifies authentication tag.
 * Also verifies integrity of additional authenticated data.
 *
 * @param ciphertext Encrypted data with 16-byte auth tag
 * @param ciphertext_len Length of ciphertext (plaintext + 16)
 * @param additional_data Authenticated metadata (must match encryption)
 * @param additional_data_len Length of additional data
 * @param nonce 12-byte nonce (must match encryption)
 * @param key 32-byte decryption key
 * @param plaintext Output buffer (at least ciphertext_len - 16 bytes)
 * @param plaintext_len Receives actual plaintext length
 * @return 0 on success, -1 on authentication failure or error
 *
 * @note Returns -1 if authentication tag is invalid (tampered data)
 * @note Returns -1 if additional data doesn't match encryption
 * @note NEVER use plaintext if this function returns -1
 */
int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *plaintext, unsigned long long *plaintext_len) {
    return crypto_aead_aes256gcm_decrypt(plaintext, plaintext_len,
                                        NULL,
                                        ciphertext, ciphertext_len,
                                        additional_data, additional_data_len,
                                        nonce, key);
}