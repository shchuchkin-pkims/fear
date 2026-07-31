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

    /* --- argument checks ----------------------------------------------------- */
    CHECK(mk_derive(NULL, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, key) != 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, NULL, key) != 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, MK_DIR_CALLER_TO_CALLEE, salt_a, NULL) != 0);
    CHECK(mk_derive(master, (mk_stream_t)7, MK_DIR_CALLER_TO_CALLEE, salt_a, key) != 0);
    CHECK(mk_derive(master, MK_STREAM_AUDIO, (mk_dir_t)9, salt_a, key) != 0);
    CHECK(mk_derive_pair(master, MK_STREAM_AUDIO, 1, salt_a, NULL, caller_recv) != 0);

    return t_report("test_media_keys");
}
