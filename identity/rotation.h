/**
 * @file rotation.h
 * @brief Room key rotation bundles (Phase C, architecture §5).
 *
 * K_room changes on every membership change: a member joins (so the new
 * member must not read past traffic) or leaves (so the leaver must not
 * read future traffic). The rotating member generates the new K_room and
 * seals it once per remaining member:
 *
 *     entry = [recipient_pk(32)][nonce(24)][ct(80)]
 *     ct    = crypto_box(K_room_new || binding, nonce,
 *                        X25519(recipient_pk), X25519(sender_sk))
 *     binding = BLAKE2b("fear.rotation.v1" || room_id || new_version
 *                       || sender_pk || recipient_pk, 32)
 *
 * The server stores the resulting bundle and hands each member their own
 * entry when they connect; it can neither read nor forge one.
 *
 * crypto_box authenticates the sender, so a recipient learns the entry
 * really came from `sender_pk`. The binding hash inside the plaintext ties
 * that entry to one room, one K_room generation and one recipient: an
 * entry replayed into another room, another version or another member's
 * slot fails to open. Whether `sender_pk` is *allowed* to rotate the room
 * is a policy question for the caller (trusted member list), not for this
 * module.
 */
#ifndef FEAR_ROTATION_H
#define FEAR_ROTATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes in K_room. */
#define ROTATION_KEY_BYTES 32

/** crypto_box nonce. */
#define ROTATION_NONCE_BYTES 24

/** Sealed plaintext is K_room(32) || binding(32); ciphertext adds a 16-byte MAC. */
#define ROTATION_CT_BYTES 80

/** One bundle entry: [recipient_pk(32)][nonce(24)][ct(80)]. */
#define ROTATION_ENTRY_BYTES (32 + ROTATION_NONCE_BYTES + ROTATION_CT_BYTES)

/** Longest room id accepted by the binding hash. */
#define ROTATION_MAX_ROOM_ID 512

/** Domain separation string for the binding hash. */
#define ROTATION_BINDING_CTX "fear.rotation.v1"

/**
 * Compute the binding hash that ties a rotation entry to one room, one
 * K_room generation, one sender and one recipient. Exposed for tests and
 * for callers that want to verify a bundle without opening it.
 *
 * @return 0 on success, -1 on bad arguments
 */
int rotation_binding(const char *room_id, uint16_t new_version,
                     const uint8_t sender_pk[32],
                     const uint8_t recipient_pk[32],
                     uint8_t out_binding[32]);

/**
 * Seal `new_k_room` for one recipient using an explicit nonce.
 * Callers should normally use rotation_seal(); this variant exists so
 * tests can pin deterministic vectors.
 *
 * @return 0 on success, -1 on bad arguments or key conversion failure
 */
int rotation_seal_with_nonce(const char *room_id, uint16_t new_version,
                             const uint8_t new_k_room[ROTATION_KEY_BYTES],
                             const uint8_t sender_sk[64],
                             const uint8_t sender_pk[32],
                             const uint8_t recipient_pk[32],
                             const uint8_t nonce[ROTATION_NONCE_BYTES],
                             uint8_t out_entry[ROTATION_ENTRY_BYTES]);

/**
 * Seal `new_k_room` for one recipient with a fresh random nonce.
 * @return 0 on success, -1 on error
 */
int rotation_seal(const char *room_id, uint16_t new_version,
                  const uint8_t new_k_room[ROTATION_KEY_BYTES],
                  const uint8_t sender_sk[64],
                  const uint8_t sender_pk[32],
                  const uint8_t recipient_pk[32],
                  uint8_t out_entry[ROTATION_ENTRY_BYTES]);

/**
 * Open the entry addressed to us and recover K_room.
 *
 * Fails if the entry is not addressed to `recipient_pk`, was not sealed by
 * `sender_pk`, belongs to another room or another version, or was altered.
 *
 * @return 0 on success, -1 on any failure (nothing is written to out_k_room)
 */
int rotation_open(const char *room_id, uint16_t new_version,
                  const uint8_t recipient_sk[64],
                  const uint8_t recipient_pk[32],
                  const uint8_t sender_pk[32],
                  const uint8_t entry[ROTATION_ENTRY_BYTES],
                  uint8_t out_k_room[ROTATION_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_ROTATION_H */
