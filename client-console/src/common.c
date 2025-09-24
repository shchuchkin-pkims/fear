#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

uint16_t rd_u16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
void wr_u16(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; }
uint32_t rd_u32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
void wr_u32(uint8_t *p, uint32_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF; }

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int recv_all(sock_t fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t*)buf;
    size_t got = 0;
    int n;
    while (got < len) {
        n = (int)recv(fd, (char*)p + got, (int)(len - got), 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

int send_all(sock_t fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t sent = 0;
    int n;
    while (sent < len) {
        n = (int)send(fd, (const char*)p + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

char *b64_encode(const uint8_t *buf, size_t len) {
    size_t outlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *out = (char*)malloc(outlen);
    if (!out) return NULL;
    sodium_bin2base64(out, outlen, buf, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return out;
}

int b64_decode(const char *b64, uint8_t *out, size_t outlen) {
    size_t real = 0;
    if (sodium_base642bin(out, outlen, b64, strlen(b64), NULL, &real, NULL,
                         sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) return -1;
    return (int)real;
}

// Функция для вычисления CRC32 (упрощенная версия)
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