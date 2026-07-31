/**
 * Test vectors and properties for room key rotation bundles (§5, Phase C).
 *
 * The expected binding hashes and ciphertexts below were produced by an
 * independent implementation (Python + PyNaCl: hashlib.blake2b for the
 * binding, crypto_box for the sealed entry) from fixed ed25519 seeds, so
 * they check the protocol and not just this code's self-consistency.
 * Any port - Android, web - must reproduce them byte for byte.
 */
#include "rotation.h"
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

/* Identities from fixed seeds: sender = 0x11 * 32, recipient = 0x22 * 32. */
static const uint8_t kSenderSeed[32] = {
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11 };
static const uint8_t kRecipientSeed[32] = {
    0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22 };

static const char kSenderPkHex[] =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
static const char kRecipientPkHex[] =
    "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";

struct vector {
    const char *room_id;
    uint16_t    version;
    const char *nonce_hex;
    const char *binding_hex;
    const char *ct_hex;
};

static const struct vector kVectors[] = {
    { "general", 2,
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7",
      "17529002237e20d7d320fc72bb80acb483847feb2a9704d5416a096f3f9c296b",
      "d4f03c9dd744df37e2d27a5f591b106d458c375fcbdd17508da510631f950cf0"
      "cba19354e87065f5dcb263c4e2959134f5baa178591af81ecb7ff5ca00c391a4"
      "8dd05399198db5ae7a6d8cb305b412d7" },
    { "pm:abc123", 7,
      "5a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071",
      "e4db51ff9d4aa859ead56d39cd023387fd006a7e9dc45c4e60b5aaa3b4a9524d",
      "8a6dc0388f14d2b39a2cdf7de56e99eacfa259e2af5caf433010de941dcc6b66"
      "af0464ba31234fbbd1a158754326de1e5432ce7e9dff67c76bbe2d3f30654153"
      "dfbd9407853736c5899e57a149871838" },
};

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t s_pk[32], s_sk[64], r_pk[32], r_sk[64];
    CHECK(crypto_sign_seed_keypair(s_pk, s_sk, kSenderSeed) == 0);
    CHECK(crypto_sign_seed_keypair(r_pk, r_sk, kRecipientSeed) == 0);

    /* The seeds must produce the identities the vectors were made with.
     * Sized for the longest thing we render: the 80-byte ciphertext. */
    char hex[2 * ROTATION_CT_BYTES + 1];
    bin2hex(s_pk, 32, hex);
    CHECK(strcmp(hex, kSenderPkHex) == 0);
    bin2hex(r_pk, 32, hex);
    CHECK(strcmp(hex, kRecipientPkHex) == 0);

    /* K_room under test: 00 01 02 ... 1f */
    uint8_t k_room[ROTATION_KEY_BYTES];
    for (size_t i = 0; i < sizeof k_room; i++) k_room[i] = (uint8_t)i;

    /* --- frozen vectors --------------------------------------------------- */
    for (size_t i = 0; i < sizeof kVectors / sizeof kVectors[0]; i++) {
        const struct vector *v = &kVectors[i];
        uint8_t nonce[ROTATION_NONCE_BYTES];
        hex2bin(v->nonce_hex, nonce, sizeof nonce);

        uint8_t binding[32];
        CHECK(rotation_binding(v->room_id, v->version, s_pk, r_pk, binding) == 0);
        bin2hex(binding, sizeof binding, hex);
        if (strcmp(hex, v->binding_hex) != 0)
            fprintf(stderr, "vector %zu binding: want %s got %s\n", i, v->binding_hex, hex);
        CHECK(strcmp(hex, v->binding_hex) == 0);

        uint8_t entry[ROTATION_ENTRY_BYTES];
        CHECK(rotation_seal_with_nonce(v->room_id, v->version, k_room,
                                       s_sk, s_pk, r_pk, nonce, entry) == 0);
        /* Entry framing: [recipient_pk][nonce][ct] */
        CHECK(memcmp(entry, r_pk, 32) == 0);
        CHECK(memcmp(entry + 32, nonce, sizeof nonce) == 0);
        bin2hex(entry + 32 + ROTATION_NONCE_BYTES, ROTATION_CT_BYTES, hex);
        if (strcmp(hex, v->ct_hex) != 0)
            fprintf(stderr, "vector %zu ct: want %s got %s\n", i, v->ct_hex, hex);
        CHECK(strcmp(hex, v->ct_hex) == 0);

        /* And it opens back to the same K_room. */
        uint8_t got[ROTATION_KEY_BYTES];
        CHECK(rotation_open(v->room_id, v->version, r_sk, r_pk, s_pk, entry, got) == 0);
        CHECK(memcmp(got, k_room, sizeof k_room) == 0);
    }

    /* --- roundtrip with a random nonce ------------------------------------- */
    uint8_t entry[ROTATION_ENTRY_BYTES], got[ROTATION_KEY_BYTES];
    CHECK(rotation_seal("general", 2, k_room, s_sk, s_pk, r_pk, entry) == 0);
    CHECK(rotation_open("general", 2, r_sk, r_pk, s_pk, entry, got) == 0);
    CHECK(memcmp(got, k_room, sizeof k_room) == 0);

    /* Two seals of the same key differ: the nonce is fresh each time. */
    uint8_t entry2[ROTATION_ENTRY_BYTES];
    CHECK(rotation_seal("general", 2, k_room, s_sk, s_pk, r_pk, entry2) == 0);
    CHECK(memcmp(entry + 32, entry2 + 32, ROTATION_NONCE_BYTES) != 0);

    /* --- what must NOT open -------------------------------------------------- */
    uint8_t t_pk[32], t_sk[64];
    CHECK(crypto_sign_keypair(t_pk, t_sk) == 0);

    /* A third party holding their own key cannot open someone else's entry. */
    CHECK(rotation_open("general", 2, t_sk, t_pk, s_pk, entry, got) != 0);
    /* Not even by claiming to be the addressee. */
    CHECK(rotation_open("general", 2, t_sk, r_pk, s_pk, entry, got) != 0);
    /* Wrong claimed sender: the box authenticates who sealed it. */
    CHECK(rotation_open("general", 2, r_sk, r_pk, t_pk, entry, got) != 0);
    /* Replay into another room or another K_room generation. */
    CHECK(rotation_open("other-room", 2, r_sk, r_pk, s_pk, entry, got) != 0);
    CHECK(rotation_open("general", 3, r_sk, r_pk, s_pk, entry, got) != 0);

    /* Tampering anywhere in the entry. */
    for (size_t pos = 0; pos < ROTATION_ENTRY_BYTES; pos += 16) {
        uint8_t evil[ROTATION_ENTRY_BYTES];
        memcpy(evil, entry, sizeof evil);
        evil[pos] ^= 0x01;
        CHECK(rotation_open("general", 2, r_sk, r_pk, s_pk, evil, got) != 0);
    }

    /* --- binding is bound to every field -------------------------------------- */
    uint8_t b1[32], b2[32];
    CHECK(rotation_binding("general", 2, s_pk, r_pk, b1) == 0);
    CHECK(rotation_binding("general", 3, s_pk, r_pk, b2) == 0);
    CHECK(memcmp(b1, b2, 32) != 0);
    CHECK(rotation_binding("generaL", 2, s_pk, r_pk, b2) == 0);
    CHECK(memcmp(b1, b2, 32) != 0);
    CHECK(rotation_binding("general", 2, r_pk, r_pk, b2) == 0);
    CHECK(memcmp(b1, b2, 32) != 0);
    CHECK(rotation_binding("general", 2, s_pk, s_pk, b2) == 0);
    CHECK(memcmp(b1, b2, 32) != 0);

    /* Bad arguments are rejected rather than half-processed. */
    CHECK(rotation_binding(NULL, 2, s_pk, r_pk, b1) != 0);
    CHECK(rotation_seal("general", 2, k_room, s_sk, s_pk, r_pk, NULL) != 0);
    CHECK(rotation_open("general", 2, r_sk, r_pk, s_pk, NULL, got) != 0);

    return t_report("test_rotation");
}
