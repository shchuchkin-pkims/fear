/**
 * @file room_keys.c
 * @brief Held K_room generations and the rotation decision (see room_keys.h).
 */
#include "room_keys.h"

#include <sodium.h>
#include <string.h>

int rk_init(room_keys_t *rk, uint16_t version, const uint8_t key[KS_KEY_BYTES]) {
    if (!rk || !key) return -1;

    rk_clear(rk);
    rk->slot[0].key.version = version;
    memcpy(rk->slot[0].key.key, key, KS_KEY_BYTES);
    rk->slot[0].expires_at = 0;      /* current: no deadline */
    rk->slot[0].in_use = 1;
    rk->current_version = version;
    return 0;
}

int rk_install(room_keys_t *rk, uint16_t version,
               const uint8_t key[KS_KEY_BYTES], uint64_t now) {
    if (!rk || !key) return -1;

    /* Already current. Saying so rather than reinstalling matters: a relay
     * that repeats a rotation bundle must not be able to keep the key it
     * replaced alive by resetting its grace period over and over. */
    for (size_t i = 0; i < CF_MAX_KEYS; i++) {
        if (rk->slot[i].in_use && rk->slot[i].key.version == version) {
            return (version == rk->current_version) ? 1 : 1;
        }
    }

    /* The outgoing generation gets a deadline; anything older than that goes
     * now, since only one generation of overlap is ever useful. */
    rk_slot_t outgoing;
    memset(&outgoing, 0, sizeof outgoing);
    int have_outgoing = 0;
    for (size_t i = 0; i < CF_MAX_KEYS; i++) {
        if (rk->slot[i].in_use && rk->slot[i].key.version == rk->current_version) {
            outgoing = rk->slot[i];
            have_outgoing = 1;
            break;
        }
    }

    rk_clear(rk);

    rk->slot[0].key.version = version;
    memcpy(rk->slot[0].key.key, key, KS_KEY_BYTES);
    rk->slot[0].expires_at = 0;
    rk->slot[0].in_use = 1;
    rk->current_version = version;

    if (have_outgoing && CF_MAX_KEYS > 1) {
        rk->slot[1] = outgoing;
        rk->slot[1].expires_at = now + RK_GRACE_SECONDS;
        rk->slot[1].in_use = 1;
    }
    return 0;
}

void rk_expire(room_keys_t *rk, uint64_t now) {
    if (!rk) return;
    for (size_t i = 0; i < CF_MAX_KEYS; i++) {
        if (!rk->slot[i].in_use) continue;
        if (rk->slot[i].expires_at == 0) continue;      /* the current one */
        if (now < rk->slot[i].expires_at) continue;
        sodium_memzero(&rk->slot[i], sizeof rk->slot[i]);
    }
}

void rk_clear(room_keys_t *rk) {
    if (!rk) return;
    sodium_memzero(rk->slot, sizeof rk->slot);
    rk->current_version = 0;
}

const cf_key_t *rk_current(const room_keys_t *rk) {
    if (!rk) return NULL;
    for (size_t i = 0; i < CF_MAX_KEYS; i++) {
        if (rk->slot[i].in_use && rk->slot[i].key.version == rk->current_version) {
            return &rk->slot[i].key;
        }
    }
    return NULL;
}

size_t rk_ring(const room_keys_t *rk, cf_key_t *out, size_t cap) {
    if (!rk || !out || cap == 0) return 0;

    size_t n = 0;
    const cf_key_t *cur = rk_current(rk);
    if (cur && n < cap) out[n++] = *cur;

    for (size_t i = 0; i < CF_MAX_KEYS && n < cap; i++) {
        if (!rk->slot[i].in_use) continue;
        if (cur && rk->slot[i].key.version == cur->version) continue;
        out[n++] = rk->slot[i].key;
    }
    return n;
}

int rk_is_rotator(const rk_member_t *members, size_t nmembers,
                  const uint8_t me[IDENTITY_PK_BYTES]) {
    if (!members || nmembers == 0 || !me) return 0;

    int me_present = 0;
    for (size_t i = 0; i < nmembers; i++) {
        if (!members[i].has_identity) continue;
        if (memcmp(members[i].pk, me, IDENTITY_PK_BYTES) == 0) {
            me_present = 1;
            break;
        }
    }
    /* Rotating a room we are not in, or cannot address a bundle from, is not
     * ours to do. */
    if (!me_present) return 0;

    for (size_t i = 0; i < nmembers; i++) {
        if (!members[i].has_identity) continue;
        if (memcmp(members[i].pk, me, IDENTITY_PK_BYTES) < 0) return 0;
    }
    return 1;
}
