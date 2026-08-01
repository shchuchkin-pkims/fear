/**
 * @file test_chat_frame.c
 * @brief Frozen vectors and refusals for a sealed chat frame.
 *
 * The sealed bytes below were produced by an implementation sharing no code
 * with this one - hashlib for BLAKE2b, the Python cryptography package for
 * AES-GCM. Android reproduces the same vector in its own unit test. Three
 * implementations agreeing on one byte string is the only evidence that the
 * platforms can read each other's chat, short of putting them in a room
 * together.
 */
#include "chat_frame.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "test_util.h"

static void bin2hex(const uint8_t *bin, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = d[bin[i] >> 4];
        out[2 * i + 1] = d[bin[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

static const char kSealedHex[] =
    "0000b2a10500d63d254b2dba6ef0704b85255ce16a7df7b208889d33f064"
    "8ac2522f82be8b5a82198c";

static const char kRoom[] = "live";
static const char kName[] = "pc";
static const char kPlain[] = "the quick brown fox";

#define EPOCH 0x0005A1B2u

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t k_room[KS_KEY_BYTES];
    for (size_t i = 0; i < sizeof k_room; i++) k_room[i] = (uint8_t)i;

    uint8_t nonce[CF_NONCE_BYTES];
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(0xA0 + i);

    size_t plen = strlen(kPlain);
    uint8_t sealed[256];
    size_t sealed_len = 0;

    /* --- the vector ------------------------------------------------------ */
    CHECK(cf_seal_at(k_room, kRoom, kName, (const uint8_t *)kPlain, plen,
                     nonce, 0, EPOCH, sealed, sizeof sealed, &sealed_len) == CF_OK);
    CHECK(sealed_len == KS_HEADER_BYTES + plen + CF_TAG_BYTES);

    char hex[2 * sizeof sealed + 1];
    bin2hex(sealed, sealed_len, hex);
    if (strcmp(hex, kSealedHex) != 0)
        fprintf(stderr, "sealed:\n want %s\n got  %s\n", kSealedHex, hex);
    CHECK(strcmp(hex, kSealedHex) == 0);

    /* The header is in the clear and names the key. */
    CHECK(sealed[0] == 0x00 && sealed[1] == 0x00);          /* key_version */
    CHECK(sealed[2] == 0xB2 && sealed[3] == 0xA1 &&
          sealed[4] == 0x05 && sealed[5] == 0x00);          /* epoch, LE */

    /* --- round trip ------------------------------------------------------ */
    uint8_t opened[256];
    size_t olen = 0;
    CHECK(cf_open_at(k_room, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_OK);
    CHECK(olen == plen);
    CHECK(memcmp(opened, kPlain, plen) == 0);

    /* One epoch either way is skew; anything further is a replay. */
    CHECK(cf_open_at(k_room, kRoom, kName, sealed, sealed_len, nonce, EPOCH + 1,
                     opened, sizeof opened, &olen) == CF_OK);
    CHECK(cf_open_at(k_room, kRoom, kName, sealed, sealed_len, nonce, EPOCH - 1,
                     opened, sizeof opened, &olen) == CF_OK);
    CHECK(cf_open_at(k_room, kRoom, kName, sealed, sealed_len, nonce, EPOCH + 2,
                     opened, sizeof opened, &olen) == CF_ERR_EPOCH);
    CHECK(cf_open_at(k_room, kRoom, kName, sealed, sealed_len, nonce, EPOCH - 2,
                     opened, sizeof opened, &olen) == CF_ERR_EPOCH);

    /* --- the header is authenticated, not merely carried ----------------- */
    {
        uint8_t evil[sizeof sealed];
        memcpy(evil, sealed, sealed_len);
        evil[2] ^= 0x01;   /* a neighbouring epoch, still inside the skew */
        CHECK(cf_open_at(k_room, kRoom, kName, evil, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_AUTH);

        memcpy(evil, sealed, sealed_len);
        evil[0] ^= 0x01;   /* a K_room generation we do not have */
        CHECK(cf_open_at(k_room, kRoom, kName, evil, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_VERSION);
    }

    /* The room and the sender are bound too: a relay cannot re-address a
     * message into another room or under another name. */
    CHECK(cf_open_at(k_room, "other", kName, sealed, sealed_len, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_ERR_AUTH);
    CHECK(cf_open_at(k_room, kRoom, "mallory", sealed, sealed_len, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_ERR_AUTH);

    /* --- refusals -------------------------------------------------------- */
    CHECK(cf_open_at(k_room, kRoom, kName, sealed, KS_HEADER_BYTES, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_ERR_TOO_SHORT);
    CHECK(cf_seal_at(k_room, kRoom, kName, (const uint8_t *)kPlain, plen, nonce,
                     0, EPOCH, sealed, plen, &sealed_len) == CF_ERR_SPACE);

    /* A different K_room derives a different epoch key, so the tag fails. */
    {
        uint8_t other[KS_KEY_BYTES];
        memcpy(other, k_room, sizeof other);
        other[0] ^= 0x01;
        CHECK(cf_seal_at(k_room, kRoom, kName, (const uint8_t *)kPlain, plen,
                         nonce, 0, EPOCH, sealed, sizeof sealed, &sealed_len) == CF_OK);
        CHECK(cf_open_at(other, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_AUTH);
    }

    printf("test_chat_frame: OK\n");
    return 0;
}
