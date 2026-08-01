/**
 * @file test_room_keys.c
 * @brief Held generations and who rotates.
 *
 * Both properties here are ones that fail quietly. A grace period that can
 * be reset by a replayed bundle keeps a retired key alive for as long as an
 * attacker keeps replaying it; a rotation rule that two members answer
 * differently produces two competing keys and a split room. Neither shows up
 * as a crash.
 */
#include "room_keys.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "test_util.h"

static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i);
}

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t k0[KS_KEY_BYTES], k1[KS_KEY_BYTES], k2[KS_KEY_BYTES];
    fill(k0, sizeof k0, 0x10);
    fill(k1, sizeof k1, 0x40);
    fill(k2, sizeof k2, 0x80);

    room_keys_t rk;
    memset(&rk, 0, sizeof rk);

    /* --- one generation -------------------------------------------------- */
    CHECK(rk_init(&rk, 0, k0) == 0);
    const cf_key_t *cur = rk_current(&rk);
    CHECK(cur != NULL && cur->version == 0);
    CHECK(memcmp(cur->key, k0, KS_KEY_BYTES) == 0);

    cf_key_t ring[CF_MAX_KEYS];
    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 1);
    CHECK(ring[0].version == 0);

    /* --- a rotation leaves the old one readable for a while -------------- */
    CHECK(rk_install(&rk, 1, k1, 1000) == 0);
    cur = rk_current(&rk);
    CHECK(cur != NULL && cur->version == 1);
    CHECK(memcmp(cur->key, k1, KS_KEY_BYTES) == 0);

    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 2);
    CHECK(ring[0].version == 1);          /* current first */
    CHECK(ring[1].version == 0);

    /* Still inside the grace period. */
    rk_expire(&rk, 1000 + RK_GRACE_SECONDS - 1);
    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 2);

    /* And then it is gone, which is the point of rotating. */
    rk_expire(&rk, 1000 + RK_GRACE_SECONDS);
    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 1);
    CHECK(ring[0].version == 1);

    /* --- a repeated bundle cannot keep a retired key alive ---------------- */
    CHECK(rk_init(&rk, 0, k0) == 0);
    CHECK(rk_install(&rk, 1, k1, 1000) == 0);
    /* The same rotation arriving again, much later. If this reset the grace
     * period, generation 0 would outlive it for as long as somebody kept
     * replaying the message. */
    CHECK(rk_install(&rk, 1, k1, 1000 + RK_GRACE_SECONDS * 10) == 1);
    rk_expire(&rk, 1000 + RK_GRACE_SECONDS);
    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 1);

    /* --- only one generation of overlap ----------------------------------- */
    CHECK(rk_init(&rk, 0, k0) == 0);
    CHECK(rk_install(&rk, 1, k1, 1000) == 0);
    CHECK(rk_install(&rk, 2, k2, 1001) == 0);
    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 2);
    CHECK(ring[0].version == 2 && ring[1].version == 1);   /* 0 is gone */

    /* --- who rotates ------------------------------------------------------ */
    rk_member_t m[3];
    memset(m, 0, sizeof m);
    for (size_t i = 0; i < 3; i++) m[i].has_identity = 1;
    memset(m[0].pk, 0x11, IDENTITY_PK_BYTES);
    memset(m[1].pk, 0x22, IDENTITY_PK_BYTES);
    memset(m[2].pk, 0x33, IDENTITY_PK_BYTES);

    /* Lowest key present, and every member computes the same answer. */
    CHECK(rk_is_rotator(m, 3, m[0].pk) == 1);
    CHECK(rk_is_rotator(m, 3, m[1].pk) == 0);
    CHECK(rk_is_rotator(m, 3, m[2].pk) == 0);

    /* The rotator leaves: the next-lowest is already the answer, with no
     * election and no message. */
    CHECK(rk_is_rotator(m + 1, 2, m[1].pk) == 1);
    CHECK(rk_is_rotator(m + 1, 2, m[2].pk) == 0);

    /* Somebody who is not in the room does not rotate it. */
    uint8_t stranger[IDENTITY_PK_BYTES];
    memset(stranger, 0x05, sizeof stranger);   /* lower than everyone */
    CHECK(rk_is_rotator(m, 3, stranger) == 0);

    /* A member without an identity is not a candidate: a bundle is addressed
     * to identity keys, so it could not seal one to anybody. */
    m[0].has_identity = 0;
    CHECK(rk_is_rotator(m, 3, m[0].pk) == 0);
    CHECK(rk_is_rotator(m, 3, m[1].pk) == 1);

    /* A room of one rotates its own key. */
    m[0].has_identity = 1;
    CHECK(rk_is_rotator(m, 1, m[0].pk) == 1);

    /* Nothing to decide from. */
    CHECK(rk_is_rotator(NULL, 0, m[0].pk) == 0);
    CHECK(rk_is_rotator(m, 3, NULL) == 0);

    /* --- clearing wipes ---------------------------------------------------- */
    CHECK(rk_init(&rk, 7, k1) == 0);
    rk_clear(&rk);
    CHECK(rk_current(&rk) == NULL);
    CHECK(rk_ring(&rk, ring, CF_MAX_KEYS) == 0);

    printf("test_room_keys: OK\n");
    return 0;
}
