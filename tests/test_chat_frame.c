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

    cf_key_t v0;
    v0.version = 0;
    memcpy(v0.key, k_room, sizeof k_room);

    uint8_t nonce[CF_NONCE_BYTES];
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(0xA0 + i);

    size_t plen = strlen(kPlain);
    uint8_t sealed[256];
    size_t sealed_len = 0;

    /* --- the vector ------------------------------------------------------ */
    CHECK(cf_seal_at(&v0, kRoom, kName, (const uint8_t *)kPlain, plen,
                     nonce, EPOCH, sealed, sizeof sealed, &sealed_len) == CF_OK);
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
    CHECK(cf_open_at(&v0, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_OK);
    CHECK(olen == plen);
    CHECK(memcmp(opened, kPlain, plen) == 0);

    /* One epoch either way is skew; anything further is a replay. */
    CHECK(cf_open_at(&v0, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH + 1,
                     opened, sizeof opened, &olen) == CF_OK);
    CHECK(cf_open_at(&v0, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH - 1,
                     opened, sizeof opened, &olen) == CF_OK);
    CHECK(cf_open_at(&v0, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH + 2,
                     opened, sizeof opened, &olen) == CF_ERR_EPOCH);
    CHECK(cf_open_at(&v0, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH - 2,
                     opened, sizeof opened, &olen) == CF_ERR_EPOCH);

    /* --- the header is authenticated, not merely carried ----------------- */
    {
        uint8_t evil[sizeof sealed];
        memcpy(evil, sealed, sealed_len);
        evil[2] ^= 0x01;   /* a neighbouring epoch, still inside the skew */
        CHECK(cf_open_at(&v0, 1, kRoom, kName, evil, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_AUTH);

        memcpy(evil, sealed, sealed_len);
        evil[0] ^= 0x01;   /* a K_room generation we do not have */
        CHECK(cf_open_at(&v0, 1, kRoom, kName, evil, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_VERSION);
    }

    /* The room and the sender are bound too: a relay cannot re-address a
     * message into another room or under another name. */
    CHECK(cf_open_at(&v0, 1, "other", kName, sealed, sealed_len, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_ERR_AUTH);
    CHECK(cf_open_at(&v0, 1, kRoom, "mallory", sealed, sealed_len, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_ERR_AUTH);

    /* --- refusals -------------------------------------------------------- */
    CHECK(cf_open_at(&v0, 1, kRoom, kName, sealed, KS_HEADER_BYTES, nonce, EPOCH,
                     opened, sizeof opened, &olen) == CF_ERR_TOO_SHORT);
    CHECK(cf_seal_at(&v0, kRoom, kName, (const uint8_t *)kPlain, plen, nonce,
                     EPOCH, sealed, plen, &sealed_len) == CF_ERR_SPACE);

    /* A different K_room derives a different epoch key, so the tag fails. */
    {
        cf_key_t other_key;
        other_key.version = 0;
        memcpy(other_key.key, k_room, sizeof other_key.key);
        other_key.key[0] ^= 0x01;
        CHECK(cf_seal_at(&v0, kRoom, kName, (const uint8_t *)kPlain, plen,
                         nonce, EPOCH, sealed, sizeof sealed, &sealed_len) == CF_OK);
        CHECK(cf_open_at(&other_key, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_AUTH);
    }

    /* --- more than one generation held at once --------------------------- */
    {
        cf_key_t ring[CF_MAX_KEYS];
        ring[0].version = 1;
        memcpy(ring[0].key, k_room, KS_KEY_BYTES);
        ring[0].key[0] ^= 0xFF;          /* a different generation entirely */
        ring[1] = v0;

        /* Sealed under 0, opened by a receiver whose current generation is 1
         * and who still holds 0. This is the message that was in flight when
         * the room rotated. */
        CHECK(cf_seal_at(&v0, kRoom, kName, (const uint8_t *)kPlain, plen,
                         nonce, EPOCH, sealed, sizeof sealed, &sealed_len) == CF_OK);
        CHECK(cf_open_at(ring, 2, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_OK);
        CHECK(olen == plen && memcmp(opened, kPlain, plen) == 0);

        /* Once generation 0 is dropped, the same frame is unreadable - which
         * is the whole point of dropping it. */
        CHECK(cf_open_at(ring, 1, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_ERR_VERSION);

        /* And a generation we hold still has to authenticate. */
        CHECK(cf_seal_at(&ring[0], kRoom, kName, (const uint8_t *)kPlain, plen,
                         nonce, EPOCH, sealed, sizeof sealed, &sealed_len) == CF_OK);
        CHECK(sealed[0] == 0x01 && sealed[1] == 0x00);      /* version 1, LE */
        CHECK(cf_open_at(ring, 2, kRoom, kName, sealed, sealed_len, nonce, EPOCH,
                         opened, sizeof opened, &olen) == CF_OK);
    }

    printf("test_chat_frame: OK\n");
    return 0;
}
