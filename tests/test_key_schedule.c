/**
 * Test vectors and properties for the room key schedule (architecture §5).
 *
 * The expected K_epoch values below were produced by an independent
 * implementation (Python hashlib.blake2b, keyed, 32-byte digest) from the
 * documented derivation
 *
 *     K_epoch = BLAKE2b(key  = K_room,
 *                       data = "fear.epoch.v1" || version_le16 || epoch_le32)
 *
 * They are frozen: any future refactor of the key schedule - including the
 * Android and web ports - must reproduce them byte for byte, or it is not
 * the same protocol.
 */
#include "key_schedule.h"
#include "test_util.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static void hex2bin(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

static void bin2hex(const uint8_t *bin, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = d[bin[i] >> 4];
        out[2 * i + 1] = d[bin[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

struct vector {
    const char *k_room_hex;
    uint16_t    version;
    uint32_t    epoch;
    const char *expected_hex;
};

static const struct vector kVectors[] = {
    /* all-zero master key, first version, first epoch */
    { "0000000000000000000000000000000000000000000000000000000000000000", 1, 0,
      "f25023dd61a1f39caf684af6fef49f8308d709b04273eba3f49a9a92e92ff05a" },
    /* next epoch, same key: completely different epoch key */
    { "0000000000000000000000000000000000000000000000000000000000000000", 1, 1,
      "a99db756901e476d212f9c2536b92b046c440e8e7c1ef27520edc1a9dbabe1e9" },
    /* same epoch, next K_room generation */
    { "0000000000000000000000000000000000000000000000000000000000000000", 2, 0,
      "4abc46ff02ab32f250fd2a4a57be044d707d1fedaa5348a7cb6f16c284dc77c8" },
    /* all-ones master key */
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1, 0,
      "c0fe04c88c024da9898edd991db408bc1837a101cb803bc228539259fe95aa20" },
    /* realistic key + a mid-2025 epoch number */
    { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1, 486000,
      "c8bf67af400d1dbd83b2027d2e9bba4ec37b1c9cf6673218829cbb0c5aa74fae" },
    /* epoch counter at its maximum */
    { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 7, 4294967295u,
      "b6ae6a8e92b082bb73e505d42b7e274c6fcd04ff4af786b57e1b8a49ef3965e0" },
};

int main(void) {
    CHECK(sodium_init() >= 0);

    /* --- frozen vectors -------------------------------------------------- */
    for (size_t i = 0; i < sizeof kVectors / sizeof kVectors[0]; i++) {
        const struct vector *v = &kVectors[i];
        uint8_t k_room[KS_KEY_BYTES], got[KS_KEY_BYTES];
        char got_hex[2 * KS_KEY_BYTES + 1];

        hex2bin(v->k_room_hex, k_room, sizeof k_room);
        CHECK(ks_derive_epoch_key(k_room, v->version, v->epoch, got) == 0);
        bin2hex(got, sizeof got, got_hex);
        if (strcmp(got_hex, v->expected_hex) != 0) {
            fprintf(stderr, "vector %zu: expected %s, got %s\n",
                    i, v->expected_hex, got_hex);
        }
        CHECK(strcmp(got_hex, v->expected_hex) == 0);
    }

    /* --- derivation properties -------------------------------------------- */
    uint8_t k_room[KS_KEY_BYTES], k_other[KS_KEY_BYTES];
    randombytes_buf(k_room, sizeof k_room);
    memcpy(k_other, k_room, sizeof k_other);
    k_other[0] ^= 0x01;

    uint8_t a[KS_KEY_BYTES], b[KS_KEY_BYTES];
    CHECK(ks_derive_epoch_key(k_room, 3, 100, a) == 0);
    CHECK(ks_derive_epoch_key(k_room, 3, 100, b) == 0);
    CHECK(memcmp(a, b, sizeof a) == 0);          /* deterministic */

    CHECK(ks_derive_epoch_key(k_room, 3, 101, b) == 0);
    CHECK(memcmp(a, b, sizeof a) != 0);          /* epoch is bound */

    CHECK(ks_derive_epoch_key(k_room, 4, 100, b) == 0);
    CHECK(memcmp(a, b, sizeof a) != 0);          /* version is bound */

    CHECK(ks_derive_epoch_key(k_other, 3, 100, b) == 0);
    CHECK(memcmp(a, b, sizeof a) != 0);          /* master key is bound */

    /* K_epoch must not simply echo K_room. */
    CHECK(memcmp(a, k_room, sizeof a) != 0);

    CHECK(ks_derive_epoch_key(NULL, 1, 0, a) != 0);
    CHECK(ks_derive_epoch_key(k_room, 1, 0, NULL) != 0);

    /* --- epoch arithmetic --------------------------------------------------- */
    CHECK(ks_epoch_from_unix(0) == 0);
    CHECK(ks_epoch_from_unix(3599) == 0);
    CHECK(ks_epoch_from_unix(3600) == 1);
    CHECK(ks_epoch_from_unix(7199) == 1);
    CHECK(ks_epoch_from_unix(486000ull * 3600ull) == 486000u);
    /* Saturates rather than wrapping onto a valid epoch. */
    CHECK(ks_epoch_from_unix(0xFFFFFFFFFFFFFFFFull) == 0xFFFFFFFFu);

    /* --- skew tolerance ------------------------------------------------------ */
    CHECK(ks_epoch_acceptable(100, 100) == 1);
    CHECK(ks_epoch_acceptable(99, 100) == 1);    /* message crossed the hour */
    CHECK(ks_epoch_acceptable(101, 100) == 1);   /* sender's clock runs ahead */
    CHECK(ks_epoch_acceptable(98, 100) == 0);
    CHECK(ks_epoch_acceptable(102, 100) == 0);
    /* No wrap-around at the ends of the range. */
    CHECK(ks_epoch_acceptable(0, 0xFFFFFFFFu) == 0);
    CHECK(ks_epoch_acceptable(0xFFFFFFFFu, 0) == 0);

    /* --- wire header ---------------------------------------------------------- */
    uint8_t hdr[KS_HEADER_BYTES];
    ks_write_header(hdr, 0x0201, 0x0A0B0C0Du);
    /* Little endian, matching the rest of the wire format. */
    CHECK(hdr[0] == 0x01 && hdr[1] == 0x02);
    CHECK(hdr[2] == 0x0D && hdr[3] == 0x0C && hdr[4] == 0x0B && hdr[5] == 0x0A);

    uint16_t ver = 0; uint32_t ep = 0;
    ks_read_header(hdr, &ver, &ep);
    CHECK(ver == 0x0201);
    CHECK(ep == 0x0A0B0C0Du);

    ks_write_header(hdr, 0xFFFF, 0xFFFFFFFFu);
    ks_read_header(hdr, &ver, &ep);
    CHECK(ver == 0xFFFF && ep == 0xFFFFFFFFu);

    return t_report("test_key_schedule");
}
