/**
 * @file stun.c
 * @brief Реализация клиента STUN
 */

#include "stun.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* Магическое число из RFC 5389. По нему STUN отличают от чего угодно
 * другого, прилетевшего на тот же порт, - а на порт для голоса прилетает
 * многое. */
#define STUN_MAGIC 0x2112A442u

#define STUN_TYPE_BINDING_REQUEST  0x0001
#define STUN_TYPE_BINDING_SUCCESS  0x0101

#define STUN_ATTR_MAPPED_ADDRESS      0x0001
#define STUN_ATTR_XOR_MAPPED_ADDRESS  0x0020

#define STUN_FAMILY_IPV4 0x01
#define STUN_FAMILY_IPV6 0x02

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

stun_status_t stun_build_request(uint8_t out[STUN_HEADER_BYTES],
                                 uint8_t txid[STUN_TXID_BYTES]) {
    if (!out || !txid) return STUN_ERR_ARGS;

    /* Идентификатор случайный и на каждый запрос новый: он и есть всё, что
     * отличает ответ на наш вопрос от пакета, присланного кем-то другим на
     * тот же порт. */
    randombytes_buf(txid, STUN_TXID_BYTES);

    wr16(out, STUN_TYPE_BINDING_REQUEST);
    wr16(out + 2, 0);                       /* атрибутов нет */
    out[4] = (uint8_t)(STUN_MAGIC >> 24);
    out[5] = (uint8_t)(STUN_MAGIC >> 16);
    out[6] = (uint8_t)(STUN_MAGIC >> 8);
    out[7] = (uint8_t)(STUN_MAGIC);
    memcpy(out + 8, txid, STUN_TXID_BYTES);
    return STUN_OK;
}

/** Записать IPv4 в точечном виде. */
static void fmt_ipv4(const uint8_t a[4], char out[STUN_MAX_ADDR]) {
    snprintf(out, STUN_MAX_ADDR, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

/**
 * Записать IPv6 в общепринятом сокращении.
 *
 * Своя реализация вместо inet_ntop потому, что заголовки для него на
 * Windows и на Unix лежат в разных местах, а этот файл собирается в обеих
 * сборках и не должен тянуть за собой сетевые заголовки ради одной строки.
 */
static void fmt_ipv6(const uint8_t a[16], char out[STUN_MAX_ADDR]) {
    uint16_t g[8];
    for (int i = 0; i < 8; i++) g[i] = (uint16_t)((a[2 * i] << 8) | a[2 * i + 1]);

    /* Самая длинная цепочка нулей сворачивается в «::» - и только она, иначе
     * адрес перестанет читаться однозначно. */
    int best_at = -1, best_len = 0, at = -1, len = 0;
    for (int i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (at < 0) { at = i; len = 1; } else { len++; }
            if (len > best_len) { best_at = at; best_len = len; }
        } else {
            at = -1; len = 0;
        }
    }
    if (best_len < 2) { best_at = -1; best_len = 0; }

    size_t o = 0;
    for (int i = 0; i < 8; ) {
        if (i == best_at) {
            o += (size_t)snprintf(out + o, STUN_MAX_ADDR - o, "::");
            i += best_len;
            /* «::» уже несёт оба двоеточия; следующая группа идёт без своего. */
            if (i < 8) {
                o += (size_t)snprintf(out + o, STUN_MAX_ADDR - o, "%x", g[i]);
                i++;
            }
            continue;
        }
        o += (size_t)snprintf(out + o, STUN_MAX_ADDR - o, "%s%x",
                              (i == 0 || i == best_at + best_len) ? "" : ":", g[i]);
        i++;
    }
    out[STUN_MAX_ADDR - 1] = '\0';
}

stun_status_t stun_parse_response(const uint8_t *buf, size_t len,
                                  const uint8_t txid[STUN_TXID_BYTES],
                                  char addr[STUN_MAX_ADDR], uint16_t *port) {
    if (!buf || !txid || !addr || !port) return STUN_ERR_ARGS;
    if (len < STUN_HEADER_BYTES) return STUN_ERR_TOO_SHORT;

    const uint32_t magic = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                           ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
    if (magic != STUN_MAGIC) return STUN_ERR_NOT_STUN;

    /* Сравнение постоянного времени тут не ради секретности: идентификатор
     * не секрет. Просто sodium_memcmp уже под рукой и не хуже. */
    if (sodium_memcmp(buf + 8, txid, STUN_TXID_BYTES) != 0) return STUN_ERR_TXID;

    if (rd16(buf) != STUN_TYPE_BINDING_SUCCESS) return STUN_ERR_TYPE;

    /* Длина объявлена отправителем, поэтому ей верить нельзя: сверяем с тем,
     * сколько байт на самом деле пришло. */
    const size_t declared = rd16(buf + 2);
    if (declared > len - STUN_HEADER_BYTES) return STUN_ERR_TOO_SHORT;

    const uint8_t *p = buf + STUN_HEADER_BYTES;
    size_t left = declared;

    while (left >= 4) {
        const uint16_t atype = rd16(p);
        const uint16_t alen  = rd16(p + 2);
        p += 4;
        left -= 4;
        if (alen > left) return STUN_ERR_TOO_SHORT;

        if (atype == STUN_ATTR_XOR_MAPPED_ADDRESS ||
            atype == STUN_ATTR_MAPPED_ADDRESS) {
            if (alen < 4) return STUN_ERR_TOO_SHORT;
            const uint8_t family = p[1];
            const int xored = (atype == STUN_ATTR_XOR_MAPPED_ADDRESS);

            uint16_t prt = rd16(p + 2);
            if (xored) prt ^= (uint16_t)(STUN_MAGIC >> 16);

            if (family == STUN_FAMILY_IPV4) {
                if (alen < 8) return STUN_ERR_TOO_SHORT;
                uint8_t a[4];
                memcpy(a, p + 4, 4);
                if (xored) {
                    a[0] ^= (uint8_t)(STUN_MAGIC >> 24);
                    a[1] ^= (uint8_t)(STUN_MAGIC >> 16);
                    a[2] ^= (uint8_t)(STUN_MAGIC >> 8);
                    a[3] ^= (uint8_t)(STUN_MAGIC);
                }
                fmt_ipv4(a, addr);
                *port = prt;
                return STUN_OK;
            }
            if (family == STUN_FAMILY_IPV6) {
                if (alen < 20) return STUN_ERR_TOO_SHORT;
                uint8_t a[16];
                memcpy(a, p + 4, 16);
                if (xored) {
                    /* Для IPv6 маской служит магическое число вместе с
                     * идентификатором запроса - ровно 16 байт. */
                    a[0] ^= (uint8_t)(STUN_MAGIC >> 24);
                    a[1] ^= (uint8_t)(STUN_MAGIC >> 16);
                    a[2] ^= (uint8_t)(STUN_MAGIC >> 8);
                    a[3] ^= (uint8_t)(STUN_MAGIC);
                    for (int i = 0; i < STUN_TXID_BYTES; i++) a[4 + i] ^= txid[i];
                }
                fmt_ipv6(a, addr);
                *port = prt;
                return STUN_OK;
            }
            return STUN_ERR_FAMILY;
        }

        /* Атрибуты выровнены по четыре байта, и добивка в объявленную длину
         * не входит. Не пропустив её, разбор поехал бы на следующем
         * атрибуте и принял мусор за заголовок. */
        size_t step = ((size_t)alen + 3u) & ~(size_t)3u;
        if (step > left) return STUN_ERR_TOO_SHORT;
        p += step;
        left -= step;
    }

    return STUN_ERR_NO_ADDRESS;
}

const char *stun_strerror(stun_status_t st) {
    switch (st) {
        case STUN_OK:             return "ok";
        case STUN_ERR_ARGS:       return "bad arguments";
        case STUN_ERR_TOO_SHORT:  return "packet shorter than it claims";
        case STUN_ERR_NOT_STUN:   return "not a STUN packet";
        case STUN_ERR_TXID:       return "reply to somebody else's request";
        case STUN_ERR_TYPE:       return "not a binding success response";
        case STUN_ERR_NO_ADDRESS: return "no address attribute";
        case STUN_ERR_FAMILY:     return "unknown address family";
    }
    return "unknown";
}
