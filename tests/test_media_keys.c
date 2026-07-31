/**
 * Test vectors and properties for sender-rooted media keys (fear.media.v2).
 *
 * Expected values were produced by an independent implementation (Python
 * hashlib.blake2b, keyed) from the derivations in
 * doc/media-key-migration.md, so this is not the code grading its own
 * homework. The Kotlin port pins the same values; if the two ever disagree,
 * desktop and Android calls stop interoperating, which is exactly the class
 * of bug these vectors exist to catch.
 *
 * Fixed inputs: K_call = 00..1f, call_id = 10..1f, saltA = a0..af,
 * saltB = 5a..69, idbind = a fixed Ed25519 pk or 32 zero bytes.
 */
#include "media_keys.h"
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

static void hex2bin(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t k_call[MK_KEY_BYTES];
    for (size_t i = 0; i < sizeof k_call; i++) k_call[i] = (uint8_t)i;

    uint8_t call_id[MK_CALLID_BYTES], call_id2[MK_CALLID_BYTES];
    uint8_t salt_a[MK_SALT_BYTES], salt_b[MK_SALT_BYTES];
    for (size_t i = 0; i < MK_CALLID_BYTES; i++) {
        call_id[i]  = (uint8_t)(0x10 + i);
        call_id2[i] = (uint8_t)(0xE0 + i);
        salt_a[i]   = (uint8_t)(0xA0 + i);
        salt_b[i]   = (uint8_t)(0x5A + i);
    }

    uint8_t pk[MK_IDBIND_BYTES], zeros[MK_IDBIND_BYTES];
    hex2bin("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
            pk, sizeof pk);
    memset(zeros, 0, sizeof zeros);

    uint8_t key[MK_KEY_BYTES];
    char hex[2 * MK_KEY_BYTES + 1];

    /* --- HELLO key ---------------------------------------------------------- */
    CHECK(mk_hello_key(k_call, call_id, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "e17ec5d029ed2987c577869ec52547ba6b2504b9ea8759c51a6d94645b967924") == 0);

    CHECK(mk_hello_key(k_call, call_id2, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "32593dd97694c649d21f9642d2a188d3918b286a374a09c725e3335cabc2a0a7") == 0);

    /* --- per-sender keys ----------------------------------------------------- */
    struct { mk_stream_t s; uint16_t kv; const uint8_t *cid, *salt, *idb; const char *want; } v[] = {
        /* unsigned audio */
        { MK_STREAM_AUDIO, 0, call_id,  salt_a, zeros,
          "0bc7ef4f1ac0a8c46391f4f153ef956893475f84be6a061d88a08139a8554de0" },
        /* unsigned video: same everything but the counter domain */
        { MK_STREAM_VIDEO, 0, call_id,  salt_a, zeros,
          "0d9837fae769f064978fd34c440199c876b0018444f78f5112ab5fda691a7460" },
        /* signed audio: identity is bound in */
        { MK_STREAM_AUDIO, 0, call_id,  salt_a, pk,
          "8a9243ecb9c62c27ba149995fe00efdb28d0e2ca5aad325ea88b86d5c3e6771e" },
        /* key_version is bound (big endian) */
        { MK_STREAM_AUDIO, 7, call_id,  salt_a, pk,
          "77c76b092b98a4fed163eda6aefbe9fd591ae8a96e703c64a3419339eef3edcf" },
        /* another sender's salt in the same call */
        { MK_STREAM_AUDIO, 0, call_id,  salt_b, pk,
          "42175bf01239d346f9ded7e88611f973ccdba9bf4e7856421fd65ebae9ba5128" },
        /* same sender, different call: a recording cannot replay across calls */
        { MK_STREAM_AUDIO, 0, call_id2, salt_a, pk,
          "cd451578c0089eb3e1d63bcb2714723ae9bbf5a65a7e5941180b18ea61077401" },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        CHECK(mk_derive_sender(k_call, v[i].s, v[i].kv, v[i].cid, v[i].salt,
                               v[i].idb, key) == 0);
        bin2hex(key, sizeof key, hex);
        if (strcmp(hex, v[i].want) != 0)
            fprintf(stderr, "key vector %zu: want %s got %s\n", i, v[i].want, hex);
        CHECK(strcmp(hex, v[i].want) == 0);
    }

    /* Every one of those differs from every other: no input is ignored. */
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++)
        for (size_t j = i + 1; j < sizeof v / sizeof v[0]; j++)
            CHECK(strcmp(v[i].want, v[j].want) != 0);

    /* --- sender tags ---------------------------------------------------------- */
    uint8_t sid[MK_SID_BYTES];
    char sid_hex[2 * MK_SID_BYTES + 1];

    CHECK(mk_sender_id(k_call, call_id, salt_a, zeros, sid) == 0);
    bin2hex(sid, sizeof sid, sid_hex);
    CHECK(strcmp(sid_hex, "0f2cee") == 0);

    CHECK(mk_sender_id(k_call, call_id, salt_a, pk, sid) == 0);
    bin2hex(sid, sizeof sid, sid_hex);
    CHECK(strcmp(sid_hex, "5338c1") == 0);

    CHECK(mk_sender_id(k_call, call_id, salt_b, pk, sid) == 0);
    bin2hex(sid, sizeof sid, sid_hex);
    CHECK(strcmp(sid_hex, "19bbc4") == 0);

    CHECK(mk_sender_id(k_call, call_id2, salt_a, pk, sid) == 0);
    bin2hex(sid, sizeof sid, sid_hex);
    CHECK(strcmp(sid_hex, "26dd22") == 0);

    /* The tag identifies a participant, not a stream: it takes no stream
     * argument, so audio and video from one sender share one tag. This is a
     * structural property of the API, asserted here so a future refactor
     * cannot quietly add a stream input. */
    uint8_t sid_again[MK_SID_BYTES];
    CHECK(mk_sender_id(k_call, call_id, salt_a, pk, sid_again) == 0);
    CHECK(mk_sender_id(k_call, call_id, salt_a, pk, sid) == 0);
    CHECK(memcmp(sid, sid_again, MK_SID_BYTES) == 0);

    /* --- HELLO MAC ------------------------------------------------------------ */
    uint8_t hello_key[MK_KEY_BYTES];
    CHECK(mk_hello_key(k_call, call_id, hello_key) == 0);

    uint8_t body[40];
    for (size_t i = 0; i < sizeof body; i++) body[i] = (uint8_t)i;

    uint8_t mac[MK_MAC_BYTES];
    char mac_hex[2 * MK_MAC_BYTES + 1];
    CHECK(mk_hello_mac(hello_key, body, sizeof body, mac) == 0);
    bin2hex(mac, sizeof mac, mac_hex);
    CHECK(strcmp(mac_hex, "a0254883e218b3ab5b22aa7a6c11dbd2") == 0);

    CHECK(mk_hello_mac_verify(hello_key, body, sizeof body, mac) == 0);

    /* A flipped bit anywhere in the body, or in the MAC, must fail. */
    for (size_t i = 0; i < sizeof body; i += 8) {
        uint8_t evil[sizeof body];
        memcpy(evil, body, sizeof evil);
        evil[i] ^= 0x01;
        CHECK(mk_hello_mac_verify(hello_key, evil, sizeof evil, mac) != 0);
    }
    uint8_t bad_mac[MK_MAC_BYTES];
    memcpy(bad_mac, mac, sizeof bad_mac);
    bad_mac[MK_MAC_BYTES - 1] ^= 0x01;
    CHECK(mk_hello_mac_verify(hello_key, body, sizeof body, bad_mac) != 0);

    /* A HELLO from another call must not verify here: that is what locks an
     * off-path attacker out of the handshake. */
    uint8_t other_hello_key[MK_KEY_BYTES];
    CHECK(mk_hello_key(k_call, call_id2, other_hello_key) == 0);
    CHECK(mk_hello_mac_verify(other_hello_key, body, sizeof body, mac) != 0);

    /* --- call_id is mandatory --------------------------------------------------- */
    uint8_t zero_call[MK_CALLID_BYTES];
    memset(zero_call, 0, sizeof zero_call);
    CHECK(mk_hello_key(k_call, zero_call, key) != 0);
    CHECK(mk_derive_sender(k_call, MK_STREAM_AUDIO, 0, zero_call, salt_a, pk, key) != 0);
    CHECK(mk_sender_id(k_call, zero_call, salt_a, pk, sid) != 0);

    /* --- argument checks --------------------------------------------------------- */
    CHECK(mk_derive_sender(NULL, MK_STREAM_AUDIO, 0, call_id, salt_a, pk, key) != 0);
    CHECK(mk_derive_sender(k_call, (mk_stream_t)7, 0, call_id, salt_a, pk, key) != 0);
    CHECK(mk_derive_sender(k_call, MK_STREAM_AUDIO, 0, call_id, salt_a, pk, NULL) != 0);
    CHECK(mk_sender_id(k_call, call_id, salt_a, NULL, sid) != 0);
    CHECK(mk_hello_key(k_call, call_id, NULL) != 0);

    return t_report("test_media_keys");
}
