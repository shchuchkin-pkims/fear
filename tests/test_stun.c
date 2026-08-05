/**
 * @file test_stun.c
 * @brief Клиент STUN: разбор ответа рассчитан на враждебный ввод
 *
 * Пакет приходит по UDP, а отправителя в UDP подделать может кто угодно.
 * Поэтому проверяется не только «правильный ответ разбирается», но и что
 * подделки, обрезки и враньё в длинах отвергаются, а не уводят разбор за
 * пределы буфера.
 */

#include "stun.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;

#define CHECK(cond) do {                                        \
    checks++;                                                   \
    if (!(cond)) {                                              \
        failures++;                                             \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
    }                                                           \
} while (0)

#define MAGIC0 0x21
#define MAGIC1 0x12
#define MAGIC2 0xA4
#define MAGIC3 0x42

/** Заготовка успешного ответа с XOR-MAPPED-ADDRESS для IPv4. */
static size_t build_xor_v4(uint8_t *out, const uint8_t *txid,
                           const uint8_t ip[4], uint16_t port) {
    out[0] = 0x01; out[1] = 0x01;          /* Binding success */
    out[2] = 0x00; out[3] = 12;            /* длина атрибутов */
    out[4] = MAGIC0; out[5] = MAGIC1; out[6] = MAGIC2; out[7] = MAGIC3;
    memcpy(out + 8, txid, STUN_TXID_BYTES);

    uint8_t *a = out + 20;
    a[0] = 0x00; a[1] = 0x20;              /* XOR-MAPPED-ADDRESS */
    a[2] = 0x00; a[3] = 8;                 /* длина значения */
    a[4] = 0x00;
    a[5] = 0x01;                            /* IPv4 */
    const uint16_t xport = (uint16_t)(port ^ 0x2112u);
    a[6] = (uint8_t)(xport >> 8);
    a[7] = (uint8_t)(xport & 0xFF);
    a[8]  = (uint8_t)(ip[0] ^ MAGIC0);
    a[9]  = (uint8_t)(ip[1] ^ MAGIC1);
    a[10] = (uint8_t)(ip[2] ^ MAGIC2);
    a[11] = (uint8_t)(ip[3] ^ MAGIC3);
    return 32;
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium init failed\n"); return 1; }

    uint8_t req[STUN_HEADER_BYTES];
    uint8_t txid[STUN_TXID_BYTES];

    /* --- запрос ---------------------------------------------------------- */
    {
        CHECK(stun_build_request(req, txid) == STUN_OK);
        CHECK(req[0] == 0x00 && req[1] == 0x01);        /* Binding request */
        CHECK(req[2] == 0 && req[3] == 0);              /* без атрибутов */
        CHECK(req[4] == MAGIC0 && req[5] == MAGIC1 &&
              req[6] == MAGIC2 && req[7] == MAGIC3);
        CHECK(memcmp(req + 8, txid, STUN_TXID_BYTES) == 0);

        /* Идентификатор на каждый запрос новый: иначе старый ответ сошёл бы
         * за новый, а чужой - за наш. */
        uint8_t req2[STUN_HEADER_BYTES], txid2[STUN_TXID_BYTES];
        CHECK(stun_build_request(req2, txid2) == STUN_OK);
        CHECK(memcmp(txid, txid2, STUN_TXID_BYTES) != 0);
    }

    /* --- обычный ответ --------------------------------------------------- */
    {
        uint8_t pkt[64];
        const uint8_t ip[4] = { 203, 0, 113, 42 };
        const size_t n = build_xor_v4(pkt, txid, ip, 51234);

        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, n, txid, addr, &port) == STUN_OK);
        CHECK(strcmp(addr, "203.0.113.42") == 0);
        CHECK(port == 51234);
    }

    /* --- ответ на чужой запрос отвергается -------------------------------
     *
     * Это главная проверка подлинности, какая тут вообще есть: на порт для
     * голоса прилетает что угодно от кого угодно.
     */
    {
        uint8_t pkt[64];
        const uint8_t ip[4] = { 198, 51, 100, 7 };
        const size_t n = build_xor_v4(pkt, txid, ip, 3478);

        uint8_t other[STUN_TXID_BYTES];
        memcpy(other, txid, sizeof other);
        other[0] ^= 0xFF;

        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, n, other, addr, &port) == STUN_ERR_TXID);
    }

    /* --- не STUN вовсе ---------------------------------------------------- */
    {
        uint8_t pkt[64];
        const uint8_t ip[4] = { 1, 2, 3, 4 };
        size_t n = build_xor_v4(pkt, txid, ip, 1234);
        pkt[4] ^= 0xFF;                       /* испортить магическое число */
        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, n, txid, addr, &port) == STUN_ERR_NOT_STUN);
    }

    /* --- враньё в длине --------------------------------------------------
     *
     * Длина атрибутов выбрана отправителем. Поверив ей, разбор ушёл бы за
     * конец буфера - ровно тот класс ошибок, ради которого этот тест есть.
     */
    {
        uint8_t pkt[64];
        const uint8_t ip[4] = { 10, 0, 0, 1 };
        size_t n = build_xor_v4(pkt, txid, ip, 1234);
        pkt[2] = 0xFF; pkt[3] = 0xFF;         /* «атрибутов на 65535 байт» */
        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, n, txid, addr, &port) == STUN_ERR_TOO_SHORT);

        /* И то же самое внутри атрибута. */
        n = build_xor_v4(pkt, txid, ip, 1234);
        pkt[20 + 2] = 0xFF; pkt[20 + 3] = 0xFF;
        CHECK(stun_parse_response(pkt, n, txid, addr, &port) == STUN_ERR_TOO_SHORT);
    }

    /* --- обрезанный пакет ------------------------------------------------- */
    {
        uint8_t pkt[64];
        const uint8_t ip[4] = { 10, 0, 0, 1 };
        const size_t n = build_xor_v4(pkt, txid, ip, 1234);
        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        for (size_t cut = 0; cut < n; cut++) {
            /* Ни одна обрезка не должна ни разобраться, ни увести разбор за
             * пределы буфера. */
            stun_status_t st = stun_parse_response(pkt, cut, txid, addr, &port);
            CHECK(st != STUN_OK);
        }
    }

    /* --- старый сервер: MAPPED-ADDRESS без XOR ---------------------------- */
    {
        uint8_t pkt[64];
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 0x01; pkt[1] = 0x01;
        pkt[2] = 0x00; pkt[3] = 12;
        pkt[4] = MAGIC0; pkt[5] = MAGIC1; pkt[6] = MAGIC2; pkt[7] = MAGIC3;
        memcpy(pkt + 8, txid, STUN_TXID_BYTES);
        uint8_t *a = pkt + 20;
        a[0] = 0x00; a[1] = 0x01;             /* MAPPED-ADDRESS */
        a[2] = 0x00; a[3] = 8;
        a[4] = 0x00; a[5] = 0x01;
        a[6] = 0x1F; a[7] = 0x90;             /* порт 8080 */
        a[8] = 192; a[9] = 0; a[10] = 2; a[11] = 33;

        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, 32, txid, addr, &port) == STUN_OK);
        CHECK(strcmp(addr, "192.0.2.33") == 0);
        CHECK(port == 8080);
    }

    /* --- адрес за неизвестным атрибутом ----------------------------------
     *
     * Серверы кладут в ответ и SOFTWARE, и другое. Пропуск неизвестного
     * атрибута обязан учитывать добивку до четырёх байт, иначе разбор
     * поедет и примет мусор за заголовок следующего.
     */
    {
        uint8_t pkt[80];
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 0x01; pkt[1] = 0x01;
        pkt[2] = 0x00; pkt[3] = 12 + 4 + 8;   /* SOFTWARE(5+3 добивки) + адрес */
        pkt[4] = MAGIC0; pkt[5] = MAGIC1; pkt[6] = MAGIC2; pkt[7] = MAGIC3;
        memcpy(pkt + 8, txid, STUN_TXID_BYTES);

        uint8_t *a = pkt + 20;
        a[0] = 0x80; a[1] = 0x22;             /* SOFTWARE */
        a[2] = 0x00; a[3] = 5;                /* пять байт - не кратно четырём */
        memcpy(a + 4, "fear", 4);
        a[8] = '!';
        /* три байта добивки уже нулевые */

        uint8_t *b = a + 4 + 8;               /* 5 + 3 добивки = 8 */
        b[0] = 0x00; b[1] = 0x20;
        b[2] = 0x00; b[3] = 8;
        b[4] = 0x00; b[5] = 0x01;
        const uint16_t xport = (uint16_t)(4444 ^ 0x2112u);
        b[6] = (uint8_t)(xport >> 8);
        b[7] = (uint8_t)(xport & 0xFF);
        b[8]  = (uint8_t)(203 ^ MAGIC0);
        b[9]  = (uint8_t)(0   ^ MAGIC1);
        b[10] = (uint8_t)(113 ^ MAGIC2);
        b[11] = (uint8_t)(9   ^ MAGIC3);

        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, 20 + 12 + 12, txid, addr, &port) == STUN_OK);
        CHECK(strcmp(addr, "203.0.113.9") == 0);
        CHECK(port == 4444);
    }

    /* --- IPv6 ------------------------------------------------------------- */
    {
        uint8_t pkt[80];
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 0x01; pkt[1] = 0x01;
        pkt[2] = 0x00; pkt[3] = 24;
        pkt[4] = MAGIC0; pkt[5] = MAGIC1; pkt[6] = MAGIC2; pkt[7] = MAGIC3;
        memcpy(pkt + 8, txid, STUN_TXID_BYTES);

        uint8_t ip6[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x01 };
        uint8_t *a = pkt + 20;
        a[0] = 0x00; a[1] = 0x20;
        a[2] = 0x00; a[3] = 20;
        a[4] = 0x00; a[5] = 0x02;             /* IPv6 */
        const uint16_t xport = (uint16_t)(9000 ^ 0x2112u);
        a[6] = (uint8_t)(xport >> 8);
        a[7] = (uint8_t)(xport & 0xFF);
        uint8_t mask[16];
        mask[0] = MAGIC0; mask[1] = MAGIC1; mask[2] = MAGIC2; mask[3] = MAGIC3;
        memcpy(mask + 4, txid, STUN_TXID_BYTES);
        for (int i = 0; i < 16; i++) a[8 + i] = (uint8_t)(ip6[i] ^ mask[i]);

        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, 20 + 24, txid, addr, &port) == STUN_OK);
        CHECK(strcmp(addr, "2001:db8::1") == 0);
        CHECK(port == 9000);
    }

    /* --- успешный ответ, но без адреса ------------------------------------ */
    {
        uint8_t pkt[32];
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 0x01; pkt[1] = 0x01;
        pkt[2] = 0x00; pkt[3] = 0;
        pkt[4] = MAGIC0; pkt[5] = MAGIC1; pkt[6] = MAGIC2; pkt[7] = MAGIC3;
        memcpy(pkt + 8, txid, STUN_TXID_BYTES);
        char addr[STUN_MAX_ADDR];
        uint16_t port = 0;
        CHECK(stun_parse_response(pkt, 20, txid, addr, &port) == STUN_ERR_NO_ADDRESS);
    }

    printf("test_stun: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
