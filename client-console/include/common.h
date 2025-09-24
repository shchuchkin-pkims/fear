#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>

#define MAX_CLIENTS 128
#define MAX_ROOM 128
#define MAX_NAME 64
#define MAX_FRAME (1 << 20)
#define DEFAULT_PORT 7777

#define MAX_FILENAME 256
#define FILE_CHUNK_SIZE (16 * 1024) // 16KB chunks
#define FILE_MAGIC 0x46494C45 // "FILE" in ASCII

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define close_socket closesocket
#define SOCK_ERR WSAGetLastError()
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
typedef int sock_t;
#define close_socket close
#define SOCK_ERR errno
#endif

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

typedef enum {
    MSG_TYPE_TEXT = 0,
    MSG_TYPE_FILE_START = 1,
    MSG_TYPE_FILE_CHUNK = 2,
    MSG_TYPE_FILE_END = 3
} message_type_t;

#endif