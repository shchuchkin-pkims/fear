#ifndef COMMON_H
#define COMMON_H

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int sock_t;
#define close_socket close
#endif

#include <stdint.h>
#include <stddef.h>

#define MAX_ROOM 256
#define MAX_NAME 256
#define MAX_FILENAME 1024
#define MAX_FRAME 65536
#define FILE_CHUNK_SIZE 8192
#define DEFAULT_PORT 8888
#define MAX_CLIENTS 100

// Message types
typedef enum {
    MSG_TYPE_TEXT = 0,
    MSG_TYPE_FILE_START = 1,
    MSG_TYPE_FILE_CHUNK = 2,
    MSG_TYPE_FILE_END = 3,
    MSG_TYPE_USER_LIST = 4
} message_type_t;

// Crypto constants for AES-256-GCM (compatible with Android)
#define CRYPTO_AEAD_AES256GCM_KEYBYTES 32
#define CRYPTO_AEAD_AES256GCM_NPUBBYTES 12
#define CRYPTO_AEAD_AES256GCM_ABYTES 16

// Для совместимости используем другие имена констант, чтобы избежать конфликтов с libsodium
#define CRYPTO_KEYBYTES CRYPTO_AEAD_AES256GCM_KEYBYTES
#define CRYPTO_NPUBBYTES CRYPTO_AEAD_AES256GCM_NPUBBYTES
#define CRYPTO_ABYTES CRYPTO_AEAD_AES256GCM_ABYTES

// Function declarations
uint16_t rd_u16(const uint8_t *p);
void wr_u16(uint8_t *p, uint16_t v);
uint32_t rd_u32(const uint8_t *p);
void wr_u32(uint8_t *p, uint32_t v);
void die(const char *msg);
int recv_all(sock_t fd, void *buf, size_t len);
int send_all(sock_t fd, const void *buf, size_t len);
char *b64_encode(const uint8_t *buf, size_t len);
int b64_decode(const char *b64, uint8_t *out, size_t outlen);
uint32_t crc32(const uint8_t *data, size_t len);

// AES-GCM функции
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *ciphertext, unsigned long long *ciphertext_len);
int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *plaintext, unsigned long long *plaintext_len);

#endif