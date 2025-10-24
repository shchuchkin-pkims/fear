/**
 * @file common.h
 * @brief Common definitions and utilities for F.E.A.R. messenger
 *
 * Provides cross-platform abstractions, protocol constants, and utility
 * function declarations used throughout the client and server modules.
 */

#ifndef COMMON_H
#define COMMON_H

/* Platform-specific socket includes and type definitions */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;              /* Windows socket type */
#define close_socket closesocket    /* Windows close function */
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int sock_t;                 /* POSIX socket type */
#define close_socket close          /* POSIX close function */
#endif

#include <stdint.h>
#include <stddef.h>

/* ===== Protocol Constants ===== */

/** Maximum room name length (including null terminator) */
#define MAX_ROOM 256

/** Maximum user name length (including null terminator) */
#define MAX_NAME 256

/** Maximum filename length for file transfers */
#define MAX_FILENAME 1024

/** Maximum frame size (messages larger than this are rejected) */
#define MAX_FRAME 65536

/** File transfer chunk size (8 KB chunks) */
#define FILE_CHUNK_SIZE 8192

/** Default server port if not specified */
#define DEFAULT_PORT 8888

/** Maximum concurrent clients per server */
#define MAX_CLIENTS 100

/* ===== Message Types ===== */

/**
 * @brief Message type identifiers for the protocol
 *
 * Each message frame includes a 1-byte type field to distinguish
 * between different kinds of messages.
 */
typedef enum {
    MSG_TYPE_TEXT = 0,        /**< Regular encrypted text message */
    MSG_TYPE_FILE_START = 1,  /**< File transfer start (metadata) */
    MSG_TYPE_FILE_CHUNK = 2,  /**< File transfer data chunk */
    MSG_TYPE_FILE_END = 3,    /**< File transfer completion */
    MSG_TYPE_USER_LIST = 4    /**< Room participant list (from server) */
} message_type_t;

/* ===== Cryptographic Constants ===== */

/**
 * AES-256-GCM parameters (chosen for Android compatibility)
 *
 * Using AES-GCM instead of XChaCha20-Poly1305 for better hardware
 * acceleration support on mobile platforms.
 */

/** AES-256-GCM key size (32 bytes / 256 bits) */
#define CRYPTO_AEAD_AES256GCM_KEYBYTES 32

/** AES-256-GCM nonce size (12 bytes / 96 bits) */
#define CRYPTO_AEAD_AES256GCM_NPUBBYTES 12

/** AES-256-GCM authentication tag size (16 bytes / 128 bits) */
#define CRYPTO_AEAD_AES256GCM_ABYTES 16

/* Shorter aliases to avoid conflicts with libsodium headers */
#define CRYPTO_KEYBYTES CRYPTO_AEAD_AES256GCM_KEYBYTES
#define CRYPTO_NPUBBYTES CRYPTO_AEAD_AES256GCM_NPUBBYTES
#define CRYPTO_ABYTES CRYPTO_AEAD_AES256GCM_ABYTES

/* ===== Function Declarations ===== */

/* Binary I/O helpers (little-endian) */
uint16_t rd_u16(const uint8_t *p);
void wr_u16(uint8_t *p, uint16_t v);
uint32_t rd_u32(const uint8_t *p);
void wr_u32(uint8_t *p, uint32_t v);

/* Error handling */
void die(const char *msg);

/* Network I/O with complete transfer guarantees */
int recv_all(sock_t fd, void *buf, size_t len);
int send_all(sock_t fd, const void *buf, size_t len);

/* Base64 encoding/decoding (URL-safe, no padding) */
char *b64_encode(const uint8_t *buf, size_t len);
int b64_decode(const char *b64, uint8_t *out, size_t outlen);

/* Data integrity */
uint32_t crc32(const uint8_t *data, size_t len);

/* AES-256-GCM encryption/decryption (AEAD) */
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *ciphertext, unsigned long long *ciphertext_len);

int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *plaintext, unsigned long long *plaintext_len);

#endif /* COMMON_H */