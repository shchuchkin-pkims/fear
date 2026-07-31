/**
 * Test vectors and properties for per-direction media keys (audit M3/M5).
 *
 * Expected values come from an independent implementation (Python
 * hashlib.blake2b, keyed) of
 *
 *     K_media = BLAKE2b(key = master, data = "fear.media.v1" || stream
 *                                            || direction || salt)
 *
 * master = 00 01 .. 1f, saltA = 10 11 .. 1f, saltB = f0 f1 .. ff.
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

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t master[MK_KEY_BYTES];
    for (size_t i = 0; i < sizeof master; i++) master[i] = (uint8_t)i;

    uint8_t salt_a[MK_SALT_BYTES], salt_b[MK_SALT_BYTES];
    for (size_t i = 0; i < MK_SALT_BYTES; i++) {
        salt_a[i] = (uint8_t)(0x10 + i);
        salt_b[i] = (uint8_t)(0xF0 ^ i);
    }

    char hex[2 * MK_KEY_BYTES + 1];
    uint8_t key[MK_KEY_BYTES];

    /* --- frozen vectors --------------------------------------------------- */
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "2115ba791b04de1beea3d49fecf95748fcf788c1ea5b4901dd534b50279a14d8") == 0);

    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLEE_TO_CALLER, salt_a, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "5dfb5ec2fe608102adb45ddb87635827891ea7b8b4b326b58ef7a27c1a12638b") == 0);

    CHECK(mk_derive(master, MK_STREAM_VIDEO, MK_DIR_CALLER_TO_CALLEE, salt_a, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "c653aba9d730f2f041d465c34fb906f36bdbb73fc4e6516dc66ccbb020645009") == 0);

    CHECK(mk_derive(master, MK_STREAM_VIDEO, MK_DIR_CALLEE_TO_CALLER, salt_a, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "0b45aa24615c1af180958bf59e949e516253a119d64baa9fd5d01f553aabb85b") == 0);

    /* Same everything but a different session salt (M5). */
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_b, key) == 0);
    bin2hex(key, sizeof key, hex);
    CHECK(strcmp(hex, "64050af487f07cc001e50c3bd1af8301e64084ef41a01d8a7047ca5de4522852") == 0);

    /* --- all four keys of a call are distinct (M3) -------------------------- */
    uint8_t k[4][MK_KEY_BYTES];
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, k[0]) == 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLEE_TO_CALLER, salt_a, k[1]) == 0);
    CHECK(mk_derive(master, MK_STREAM_VIDEO, MK_DIR_CALLER_TO_CALLEE, salt_a, k[2]) == 0);
    CHECK(mk_derive(master, MK_STREAM_VIDEO, MK_DIR_CALLEE_TO_CALLER, salt_a, k[3]) == 0);
    for (int i = 0; i < 4; i++) {
        CHECK(memcmp(k[i], master, MK_KEY_BYTES) != 0);
        for (int j = i + 1; j < 4; j++) CHECK(memcmp(k[i], k[j], MK_KEY_BYTES) != 0);
    }

    /* A different session salt changes every key. */
    uint8_t k_b[MK_KEY_BYTES];
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_b, k_b) == 0);
    CHECK(memcmp(k_b, k[0], MK_KEY_BYTES) != 0);

    /* So does a different master key. */
    uint8_t other_master[MK_KEY_BYTES];
    memcpy(other_master, master, sizeof other_master);
    other_master[31] ^= 0x01;
    CHECK(mk_derive(other_master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, k_b) == 0);
    CHECK(memcmp(k_b, k[0], MK_KEY_BYTES) != 0);

    /* --- the two ends agree ------------------------------------------------- */
    uint8_t caller_send[MK_KEY_BYTES], caller_recv[MK_KEY_BYTES];
    uint8_t callee_send[MK_KEY_BYTES], callee_recv[MK_KEY_BYTES];
    CHECK(mk_derive_pair(master, MK_STREAM_AUDIO, 1, salt_a, caller_send, caller_recv) == 0);
    CHECK(mk_derive_pair(master, MK_STREAM_AUDIO, 0, salt_a, callee_send, callee_recv) == 0);
    /* What one side encrypts with, the other decrypts with. */
    CHECK(memcmp(caller_send, callee_recv, MK_KEY_BYTES) == 0);
    CHECK(memcmp(callee_send, caller_recv, MK_KEY_BYTES) == 0);
    /* And a peer never sends and receives under the same key. */
    CHECK(memcmp(caller_send, caller_recv, MK_KEY_BYTES) != 0);
    CHECK(memcmp(callee_send, callee_recv, MK_KEY_BYTES) != 0);

    /* Video pair is independent of the audio pair. */
    uint8_t v_send[MK_KEY_BYTES], v_recv[MK_KEY_BYTES];
    CHECK(mk_derive_pair(master, MK_STREAM_VIDEO, 1, salt_a, v_send, v_recv) == 0);
    CHECK(memcmp(v_send, caller_send, MK_KEY_BYTES) != 0);
    CHECK(memcmp(v_recv, caller_recv, MK_KEY_BYTES) != 0);

    /* --- salt agreement: frozen vectors ------------------------------------- */
    /* Independently computed with Python hashlib.blake2b(key=master,
     * digest_size=16) over "fear.media.salt.v1" || lo || hi. */
    uint8_t half_c[MK_SALT_BYTES];
    memset(half_c, 0, sizeof half_c);
    half_c[MK_SALT_BYTES - 1] = 0x01;

    uint8_t salt[MK_SALT_BYTES];
    char salt_hex[2 * MK_SALT_BYTES + 1];

    CHECK(mk_salt_combine(master, salt_a, salt_b, salt) == 0);
    bin2hex(salt, sizeof salt, salt_hex);
    CHECK(strcmp(salt_hex, "72f75f37beebffb6d9da8920b9045063") == 0);

    /* Commutative: the two ends must not have to agree who spoke first. */
    uint8_t salt_rev[MK_SALT_BYTES];
    CHECK(mk_salt_combine(master, salt_b, salt_a, salt_rev) == 0);
    CHECK(memcmp(salt, salt_rev, sizeof salt) == 0);

    uint8_t zero_master[MK_KEY_BYTES];
    memset(zero_master, 0, sizeof zero_master);
    CHECK(mk_salt_combine(zero_master, salt_a, salt_b, salt) == 0);
    bin2hex(salt, sizeof salt, salt_hex);
    CHECK(strcmp(salt_hex, "ef6cdd21ef8fb871e10d248a13f3be87") == 0);

    CHECK(mk_salt_combine(master, salt_a, half_c, salt) == 0);
    bin2hex(salt, sizeof salt, salt_hex);
    CHECK(strcmp(salt_hex, "6c6d840e804427679a352df05065fd2b") == 0);

    /* Every input is bound: change the peer half or the master, get a
     * different salt. */
    uint8_t salt_ab[MK_SALT_BYTES], salt_ac[MK_SALT_BYTES], salt_other[MK_SALT_BYTES];
    CHECK(mk_salt_combine(master, salt_a, salt_b, salt_ab) == 0);
    CHECK(mk_salt_combine(master, salt_a, half_c, salt_ac) == 0);
    CHECK(memcmp(salt_ab, salt_ac, MK_SALT_BYTES) != 0);
    CHECK(mk_salt_combine(other_master, salt_a, salt_b, salt_other) == 0);
    CHECK(memcmp(salt_ab, salt_other, MK_SALT_BYTES) != 0);

    /* --- role assignment ------------------------------------------------------ */
    int a_is_caller = -1, b_is_caller = -1;
    CHECK(mk_role_from_halves(salt_a, salt_b, &a_is_caller) == 0);
    CHECK(mk_role_from_halves(salt_b, salt_a, &b_is_caller) == 0);
    /* Opposite by construction, whichever half happens to be smaller. */
    CHECK(a_is_caller != b_is_caller);
    CHECK(a_is_caller == 1);   /* 0x10.. sorts before 0xf0.. */

    /* A reflected HELLO (our own half coming back) must be refused, not
     * resolved: either answer would put both ends on one key at seq 0. */
    int dummy = -1;
    CHECK(mk_role_from_halves(salt_a, salt_a, &dummy) != 0);
    CHECK(mk_salt_combine(NULL, salt_a, salt_b, salt) != 0);
    CHECK(mk_role_from_halves(salt_a, salt_b, NULL) != 0);

    /* --- end to end: two peers reach the same keys -------------------------- */
    /* Peer A knows only its own half and the one it received, and vice
     * versa; nothing else is exchanged. */
    uint8_t a_salt[MK_SALT_BYTES], b_salt[MK_SALT_BYTES];
    int a_role = 0, b_role = 0;
    CHECK(mk_salt_combine(master, salt_a, salt_b, a_salt) == 0);
    CHECK(mk_role_from_halves(salt_a, salt_b, &a_role) == 0);
    CHECK(mk_salt_combine(master, salt_b, salt_a, b_salt) == 0);
    CHECK(mk_role_from_halves(salt_b, salt_a, &b_role) == 0);
    CHECK(memcmp(a_salt, b_salt, MK_SALT_BYTES) == 0);

    for (int stream = MK_STREAM_AUDIO; stream <= MK_STREAM_VIDEO; stream++) {
        uint8_t a_tx[MK_KEY_BYTES], a_rx[MK_KEY_BYTES];
        uint8_t b_tx[MK_KEY_BYTES], b_rx[MK_KEY_BYTES];
        CHECK(mk_derive_pair(master, (mk_stream_t)stream, a_role, a_salt, a_tx, a_rx) == 0);
        CHECK(mk_derive_pair(master, (mk_stream_t)stream, b_role, b_salt, b_tx, b_rx) == 0);
        /* What A encrypts, B decrypts, and neither reuses a key. */
        CHECK(memcmp(a_tx, b_rx, MK_KEY_BYTES) == 0);
        CHECK(memcmp(b_tx, a_rx, MK_KEY_BYTES) == 0);
        CHECK(memcmp(a_tx, a_rx, MK_KEY_BYTES) != 0);
    }

    /* --- argument checks ----------------------------------------------------- */
    CHECK(mk_derive(NULL, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, key) != 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, NULL, key) != 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, NULL) != 0);
    CHECK(mk_derive(master, (mk_stream_t)7, MK_DIR_CALLER_TO_CALLEE, salt_a, key) != 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, (mk_dir_t)9, salt_a, key) != 0);
    CHECK(mk_derive_pair(master, MK_STREAM_AUDIO, 1, salt_a, NULL, caller_recv) != 0);

    return t_report("test_media_keys");
}
