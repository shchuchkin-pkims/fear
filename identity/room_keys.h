/**
 * @file room_keys.h
 * @brief Which K_room generations we hold, and who rotates (Phase C).
 *
 * Two decisions live here, both of them the kind that go wrong quietly if
 * they are spread across a network handler.
 *
 * **What we can still read.** A rotation replaces the room key, but the
 * messages already in flight were sealed under the generation it replaced
 * and arrive afterwards. Dropping the old key the moment the new one
 * arrives loses them. So the previous generation is kept for a short grace
 * period and then destroyed - short, because the whole purpose of rotating
 * is that the old key stops existing, and every second it is still around
 * is a second of that purpose not yet delivered.
 *
 * **Who rotates.** The member whose identity fingerprint is lowest among
 * those present. Every member computes the same answer from the same
 * roster, so nobody has to be elected and nothing has to be agreed: there
 * is no message, no timer and no tie to break. If that member is the one
 * leaving, the roster they left is the roster everyone else evaluates, and
 * the next-lowest is already the answer.
 *
 * A member without an identity cannot be chosen. It could not seal a bundle
 * to anyone, since rotation entries are addressed to identity keys.
 *
 * This module is deliberately free of I/O: it decides and it remembers,
 * and the caller does the talking. That is what lets both decisions be
 * tested without a socket, a clock or a peer.
 */
#ifndef FEAR_ROOM_KEYS_H
#define FEAR_ROOM_KEYS_H

#include <stddef.h>
#include <stdint.h>

#include "chat_frame.h"
#include "identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * How long a superseded generation stays readable, in seconds.
 *
 * Long enough for anything already on the wire when the rotation landed;
 * short enough that "the old key is gone" is nearly true immediately. It is
 * not a delivery guarantee: a peer that was offline through the rotation
 * needs the new key, not the old one.
 */
#define RK_GRACE_SECONDS 60

/** One held generation. */
typedef struct {
    cf_key_t key;
    /** When this generation stops being readable; 0 means never. */
    uint64_t expires_at;
    int      in_use;
} rk_slot_t;

/** The generations we hold. Current first. */
typedef struct {
    rk_slot_t slot[CF_MAX_KEYS];
    uint16_t  current_version;
} room_keys_t;

/**
 * Start holding one generation, forgetting anything held before.
 * @return 0 on success, -1 on bad arguments
 */
int rk_init(room_keys_t *rk, uint16_t version, const uint8_t key[KS_KEY_BYTES]);

/**
 * Take a new generation into use, keeping the outgoing one readable until
 * `now + RK_GRACE_SECONDS`.
 *
 * A version we already hold is not reinstalled: a rotation bundle repeated
 * by a relay must not reset the grace period on the key it replaced, or the
 * old key could be kept alive indefinitely by replaying one message.
 *
 * @param now current time in seconds
 * @return 0 if installed, 1 if it was already current, -1 on bad arguments
 */
int rk_install(room_keys_t *rk, uint16_t version,
               const uint8_t key[KS_KEY_BYTES], uint64_t now);

/** Destroy every generation whose grace period has passed. */
void rk_expire(room_keys_t *rk, uint64_t now);

/** Destroy every generation held, wiping the key material. */
void rk_clear(room_keys_t *rk);

/**
 * The generation to seal under: always the current one, never an older.
 * @return NULL if nothing is held
 */
const cf_key_t *rk_current(const room_keys_t *rk);

/**
 * Fill `out` with every generation still readable, current first.
 * @return how many were written
 */
size_t rk_ring(const room_keys_t *rk, cf_key_t *out, size_t cap);

/** One member of a room, as rotation needs to see them. */
typedef struct {
    /** Ed25519 identity key. */
    uint8_t pk[IDENTITY_PK_BYTES];
    /** Zero when this member announced no identity. */
    int has_identity;
} rk_member_t;

/**
 * Whether `me` is the member who should rotate the room key.
 *
 * The lowest identity key present wins, compared as bytes. `me` must be one
 * of `members`; if it is not, or if it has no identity, the answer is no.
 *
 * @return 1 if we should rotate, 0 otherwise
 */
int rk_is_rotator(const rk_member_t *members, size_t nmembers,
                  const uint8_t me[IDENTITY_PK_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_ROOM_KEYS_H */
