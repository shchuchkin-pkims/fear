/**
 * @file media_keys.h
 * @brief Per-direction media keys with a session salt (Phase C, audit M3/M5).
 *
 * The call media path used to encrypt both directions under one key,
 * separating the two senders only by a random 4-byte nonce prefix, and it
 * derived that key deterministically from the room key. Two consequences:
 *
 *   M3  both peers restart their sequence counter at 0, so a prefix
 *       collision (~2^-32 per call) means the same key/nonce pair encrypts
 *       two different packets - the classic GCM catastrophe
 *   M5  the same room key always produced the same media key, so nonce
 *       collisions accumulate across sessions instead of being confined
 *       to one call
 *
 * Both go away if the key differs per direction and per session:
 *
 *     K_media = BLAKE2b(key  = K_call,
 *                       data = "fear.media.v1" || stream || direction || salt,
 *                       out  = 32)
 *
 * `salt` is 16 bytes agreed in the HELLO handshake. It is public - it only
 * needs to be unique per call, not secret. With distinct keys per
 * direction, both peers may start at sequence 0 with no risk.
 *
 * Salt agreement (mk_salt_combine): each peer sends its own random half in
 * its HELLO and both sides fold the two halves together. Neither end can
 * pick the session salt alone, so a peer that reuses a half - a replayed
 * HELLO, a broken RNG - cannot force the other side back onto a salt it has
 * already used. The fold is commutative, so both ends reach the same value
 * without knowing who spoke first.
 *
 * Role assignment (mk_role_from_halves): the direction bit comes from the
 * halves themselves rather than from who dialled. The two ends therefore
 * cannot disagree about it, which matters because "am I the caller" is not
 * reliably known at every call site today (the relay path hardcodes it).
 */
#ifndef FEAR_MEDIA_KEYS_H
#define FEAR_MEDIA_KEYS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Derived media key length (AES-256-GCM). */
#define MK_KEY_BYTES 32

/** Session salt length, exchanged in HELLO. */
#define MK_SALT_BYTES 16

/** Domain separation string for the media keys. */
#define MK_CTX "fear.media.v1"

/** Domain separation string for folding the two HELLO halves into a salt. */
#define MK_SALT_CTX "fear.media.salt.v1"

/** Which stream the key protects. */
typedef enum {
    MK_STREAM_AUDIO = 0,
    MK_STREAM_VIDEO = 1
} mk_stream_t;

/** Which direction the key protects. */
typedef enum {
    MK_DIR_CALLER_TO_CALLEE = 0,
    MK_DIR_CALLEE_TO_CALLER = 1
} mk_dir_t;

/**
 * Fold the two HELLO halves into the session salt:
 *
 *     salt = BLAKE2b(key  = master,
 *                    data = "fear.media.salt.v1" || lo || hi,
 *                    out  = 16)
 *
 * where lo/hi are the two halves ordered by memcmp, which makes the result
 * commutative: both ends compute it without agreeing who is "first". The
 * master key is folded in as well, so the salt of one room's call cannot be
 * replayed into another room even if an attacker replays both halves.
 *
 * @return 0 on success, -1 on bad arguments or hash failure
 */
int mk_salt_combine(const uint8_t master[MK_KEY_BYTES],
                    const uint8_t half_a[MK_SALT_BYTES],
                    const uint8_t half_b[MK_SALT_BYTES],
                    uint8_t out_salt[MK_SALT_BYTES]);

/**
 * Decide the direction bit from the two halves: the peer whose half is
 * smaller by memcmp is the caller. Both ends see the same pair and reach
 * opposite answers.
 *
 * Equal halves are refused rather than resolved. That case means either a
 * 1-in-2^128 coincidence or - far more likely - a peer reflecting our own
 * HELLO back at us, and picking either role there would put both ends on
 * the same key with both sequence counters at 0, which is precisely the
 * nonce reuse this module exists to prevent. The caller must abandon the
 * call. Note this is a denial-of-service surface for unsigned calls: a peer
 * able to reflect datagrams can force a teardown. Losing the call beats
 * losing the encryption.
 *
 * @param out_is_caller receives 1 if we are the caller, 0 if the callee
 * @return 0 on success, -1 on bad arguments or equal halves
 */
int mk_role_from_halves(const uint8_t local_half[MK_SALT_BYTES],
                        const uint8_t peer_half[MK_SALT_BYTES],
                        int *out_is_caller);

/**
 * Derive one directional media key.
 *
 * @param master  32-byte call master key (room key or ECDH result)
 * @param stream  audio or video
 * @param dir     which direction this key protects
 * @param salt    16-byte session salt from the HELLO handshake
 * @param out_key receives the 32-byte key
 * @return 0 on success, -1 on bad arguments or hash failure
 */
int mk_derive(const uint8_t master[MK_KEY_BYTES],
              mk_stream_t stream, mk_dir_t dir,
              const uint8_t salt[MK_SALT_BYTES],
              uint8_t out_key[MK_KEY_BYTES]);

/**
 * Derive both keys a peer needs, picking directions from its role.
 * The caller's send key is the callee's receive key and vice versa, so
 * both ends call this and get a matching pair.
 *
 * @param is_caller  non-zero for the side that initiated the call
 * @return 0 on success, -1 on error
 */
int mk_derive_pair(const uint8_t master[MK_KEY_BYTES],
                   mk_stream_t stream, int is_caller,
                   const uint8_t salt[MK_SALT_BYTES],
                   uint8_t out_send[MK_KEY_BYTES],
                   uint8_t out_recv[MK_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_MEDIA_KEYS_H */
