/**
 * HELLO2 codec: frozen byte vectors, per-offset assertions and the full
 * rejection matrix.
 *
 * The two expected packets were produced by an independent implementation
 * (Python + PyNaCl) from the layout in doc/media-key-migration.md, so a
 * framing mistake here cannot hide behind this code agreeing with itself.
 * The Kotlin port pins the same bytes.
 */
#include "media_hello.h"
#include "test_util.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static void bin2hex(const uint8_t *bin, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = d[bin[i] >> 4];
        out[2 * i + 1] = d[bin[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

static const char kUnsignedHex[] =
    "7e03003e02000000101112131415161718191a1b1c1d1e1f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000"
    "aa0038d7725c725308478760018f5ff7";

static const char kSignedHex[] =
    "7e03009e07000007101112131415161718191a1b1c1d1e1f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf028001e01900"
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    "2b9b4a45c4c2ad7d835677dc6260ee0e27bf2946ef62d0b7cc0f523f30ace05c"
    "05b6c4f80cb90ca59da76b41cdaeec7f45833f1eb7ebba16cbad2577d9bc9505"
    "fdab26ee8e43dcce31a1bd07ae56e7da";

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t k_call[MK_KEY_BYTES];
    for (size_t i = 0; i < sizeof k_call; i++) k_call[i] = (uint8_t)i;

    uint8_t call_id[MK_CALLID_BYTES], salt[MK_SALT_BYTES];
    for (size_t i = 0; i < MK_CALLID_BYTES; i++) {
        call_id[i] = (uint8_t)(0x10 + i);
        salt[i]    = (uint8_t)(0xA0 + i);
    }

    uint8_t hello_key[MK_KEY_BYTES];
    CHECK(mk_hello_key(k_call, call_id, hello_key) == 0);

    uint8_t seed[32], pk[32], sk[64];
    memset(seed, 0x11, sizeof seed);
    CHECK(crypto_sign_seed_keypair(pk, sk, seed) == 0);

    uint8_t pkt[MH_SIZE_SIGNED];
    size_t pkt_len = 0;
    char hex[2 * MH_SIZE_SIGNED + 1];

    /* --- unsigned, audio only ------------------------------------------------ */
    mh_hello_t in;
    memset(&in, 0, sizeof in);
    in.flags = MH_FLAG_AUDIO;
    in.key_version = 0;
    memcpy(in.call_id, call_id, sizeof call_id);
    memcpy(in.sender_salt, salt, sizeof salt);

    CHECK(mh_build(&in, hello_key, NULL, pkt, sizeof pkt, &pkt_len) == MH_OK);
    CHECK(pkt_len == MH_SIZE_BASE);
    bin2hex(pkt, pkt_len, hex);
    if (strcmp(hex, kUnsignedHex) != 0)
        fprintf(stderr, "unsigned:\n want %s\n got  %s\n", kUnsignedHex, hex);
    CHECK(strcmp(hex, kUnsignedHex) == 0);

    /* Per-offset assertions, so a mistake points at the field. */
    CHECK(pkt[0] == MH_TYPE);
    CHECK(pkt[1] == MH_VERSION);
    CHECK(pkt[2] == 0x00 && pkt[3] == 0x3E);            /* length, big endian */
    CHECK(pkt[4] == MH_FLAG_AUDIO);
    CHECK(pkt[5] == 0);
    CHECK(pkt[6] == 0 && pkt[7] == 0);                  /* key_version */
    CHECK(memcmp(pkt + 8, call_id, MK_CALLID_BYTES) == 0);
    CHECK(memcmp(pkt + 24, salt, MK_SALT_BYTES) == 0);
    /* Video parameters zeroed when the flag is clear. */
    for (size_t i = 40; i < 46; i++) CHECK(pkt[i] == 0);

    mh_hello_t got;
    CHECK(mh_parse(pkt, pkt_len, hello_key, &got) == MH_OK);
    CHECK(got.flags == MH_FLAG_AUDIO);
    CHECK(got.key_version == 0);
    CHECK(memcmp(got.call_id, call_id, MK_CALLID_BYTES) == 0);
    CHECK(memcmp(got.sender_salt, salt, MK_SALT_BYTES) == 0);
    CHECK(got.width == 0 && got.height == 0 && got.fps == 0);

    /* --- signed, audio + video ----------------------------------------------- */
    memset(&in, 0, sizeof in);
    in.flags = MH_FLAG_VIDEO | MH_FLAG_AUDIO | MH_FLAG_IDENTITY;
    in.key_version = 7;
    memcpy(in.call_id, call_id, sizeof call_id);
    memcpy(in.sender_salt, salt, sizeof salt);
    in.width = 640; in.height = 480; in.fps = 25;

    CHECK(mh_build(&in, hello_key, sk, pkt, sizeof pkt, &pkt_len) == MH_OK);
    CHECK(pkt_len == MH_SIZE_SIGNED);
    bin2hex(pkt, pkt_len, hex);
    if (strcmp(hex, kSignedHex) != 0)
        fprintf(stderr, "signed:\n want %s\n got  %s\n", kSignedHex, hex);
    CHECK(strcmp(hex, kSignedHex) == 0);

    CHECK(pkt[2] == 0x00 && pkt[3] == 0x9E);
    CHECK(pkt[6] == 0x00 && pkt[7] == 0x07);
    CHECK(pkt[40] == 0x02 && pkt[41] == 0x80);          /* width 640 */
    CHECK(pkt[42] == 0x01 && pkt[43] == 0xE0);          /* height 480 */
    CHECK(pkt[44] == 25);
    CHECK(memcmp(pkt + 46, pk, 32) == 0);

    CHECK(mh_parse(pkt, pkt_len, hello_key, &got) == MH_OK);
    CHECK(got.key_version == 7);
    CHECK(got.width == 640 && got.height == 480 && got.fps == 25);
    CHECK(memcmp(got.pk, pk, 32) == 0);

    /* --- the signature covers the whole header ------------------------------- */
    /* Flip a bit in each signed field, re-MAC so the MAC is not what fails,
     * and check the signature catches it. */
    for (size_t pos = 0; pos < 78; pos += 7) {
        uint8_t evil[MH_SIZE_SIGNED];
        memcpy(evil, pkt, sizeof evil);
        evil[pos] ^= 0x01;
        CHECK(mk_hello_mac(hello_key, evil, MH_SIZE_SIGNED - MK_MAC_BYTES,
                           evil + MH_SIZE_SIGNED - MK_MAC_BYTES) == 0);
        mh_status_t st = mh_parse(evil, MH_SIZE_SIGNED, hello_key, &got);
        /* Byte 0..5 corruption is caught structurally; the rest by the sig. */
        CHECK(st != MH_OK);
    }

    /* --- the MAC gates everything ------------------------------------------- */
    uint8_t evil[MH_SIZE_SIGNED];
    memcpy(evil, pkt, sizeof evil);
    evil[MH_SIZE_SIGNED - 1] ^= 0x01;
    CHECK(mh_parse(evil, MH_SIZE_SIGNED, hello_key, &got) == MH_ERR_MAC);

    /* A HELLO from another call must not be accepted here. */
    uint8_t other_call[MK_CALLID_BYTES], other_key[MK_KEY_BYTES];
    memset(other_call, 0xE0, sizeof other_call);
    CHECK(mk_hello_key(k_call, other_call, other_key) == 0);
    CHECK(mh_parse(pkt, pkt_len, other_key, &got) == MH_ERR_MAC);

    /* --- rejection matrix ----------------------------------------------------- */
    /* Each case re-MACs after tampering, so we test the structural rule and
     * not merely that the MAC noticed. */
    #define REMAC_AND_PARSE(buf, n) ( \
        mk_hello_mac(hello_key, (buf), (n) - MK_MAC_BYTES, \
                     (buf) + (n) - MK_MAC_BYTES), \
        mh_parse((buf), (n), hello_key, &got) )

    /* wrong version */
    memcpy(evil, pkt, sizeof evil);
    evil[1] = 0x02;
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_VERSION);

    /* reserved flag bit set */
    memcpy(evil, pkt, sizeof evil);
    evil[4] |= 0x10;
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_RESERVED);

    /* reserved bytes set */
    memcpy(evil, pkt, sizeof evil);
    evil[5] = 0x01;
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_RESERVED);
    memcpy(evil, pkt, sizeof evil);
    evil[45] = 0x01;
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_RESERVED);

    /* IDENTITY clear but the packet is 158 bytes long */
    memcpy(evil, pkt, sizeof evil);
    evil[4] &= (uint8_t)~MH_FLAG_IDENTITY;
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_LENGTH);

    /* declared length disagrees with the real one */
    memcpy(evil, pkt, sizeof evil);
    evil[2] = 0x00; evil[3] = 0x3E;
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_LENGTH);

    /* all-zero call_id */
    memcpy(evil, pkt, sizeof evil);
    memset(evil + 8, 0, MK_CALLID_BYTES);
    CHECK(REMAC_AND_PARSE(evil, MH_SIZE_SIGNED) == MH_ERR_CALLID);

    /* truncation and trailing bytes */
    CHECK(mh_parse(pkt, MH_SIZE_SIGNED - 1, hello_key, &got) != MH_OK);
    CHECK(mh_parse(pkt, MK_MAC_BYTES, hello_key, &got) != MH_OK);
    CHECK(mh_parse(pkt, 0, hello_key, &got) != MH_OK);

    /* --- old peers are named, not silently dropped ---------------------------- */
    uint8_t legacy[107];
    memset(legacy, 0, sizeof legacy);
    legacy[0] = 0x7F;
    CHECK(mh_parse(legacy, 5, hello_key, &got) == MH_ERR_LEGACY_PEER);
    CHECK(mh_parse(legacy, 102, hello_key, &got) == MH_ERR_LEGACY_PEER);
    CHECK(mh_parse(legacy, sizeof legacy, hello_key, &got) == MH_ERR_LEGACY_PEER);

    uint8_t alien[MH_SIZE_BASE];
    memset(alien, 0, sizeof alien);
    alien[0] = 0x01;
    CHECK(mh_parse(alien, sizeof alien, hello_key, &got) == MH_ERR_TYPE);

    /* --- build-side argument checks ------------------------------------------- */
    memset(&in, 0, sizeof in);
    in.flags = MH_FLAG_AUDIO;
    memcpy(in.call_id, call_id, sizeof call_id);
    CHECK(mh_build(&in, hello_key, NULL, pkt, MH_SIZE_BASE - 1, &pkt_len) == MH_ERR_ARGS);

    in.flags = MH_FLAG_AUDIO | MH_FLAG_IDENTITY;
    CHECK(mh_build(&in, hello_key, NULL, pkt, sizeof pkt, &pkt_len) == MH_ERR_ARGS);

    in.flags = MH_FLAG_AUDIO | 0x20;
    CHECK(mh_build(&in, hello_key, NULL, pkt, sizeof pkt, &pkt_len) == MH_ERR_RESERVED);

    in.flags = MH_FLAG_AUDIO;
    memset(in.call_id, 0, sizeof in.call_id);
    CHECK(mh_build(&in, hello_key, NULL, pkt, sizeof pkt, &pkt_len) == MH_ERR_CALLID);

    CHECK(mh_size(MH_FLAG_AUDIO) == MH_SIZE_BASE);
    CHECK(mh_size(MH_FLAG_AUDIO | MH_FLAG_IDENTITY) == MH_SIZE_SIGNED);
    CHECK(mh_strerror(MH_ERR_LEGACY_PEER) != NULL);

    return t_report("test_media_hello");
}
