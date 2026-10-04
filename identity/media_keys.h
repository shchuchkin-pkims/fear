/**
 * @file media_keys.h
 * @brief Sender-rooted media keys for group calls (Phase C, audit M3/M5).
 *
 * Every participant encrypts under a key nobody else uses, derived from the
 * shared call key and that participant's own public announcement:
 *
 *     K_send(P, stream) = BLAKE2b(key  = K_call,
 *                                 data = "fear.media.v2" || stream
 *                                        || key_version || call_id
 *                                        || sender_salt || idbind,
 *                                 out  = 32)
 *
 * There is no agreement step. A receiver derives any peer's key from K_call
 * plus the salt, key_version and identity that peer announced in its HELLO,
 * so nothing has to be negotiated, no role has to be decided, and a
 * participant joining or leaving changes nobody else's keys. That is what
 * makes group calls work: the old scheme keyed on a caller/callee bit, and
 * with three participants the last HELLO won and every receive key but one
 * was wrong.
 *
 * Two audit items close here. Both directions of a call used to share one
 * key, separated only by a 4-byte nonce prefix while both peers started
 * their counter at 0, so a prefix collision reused a (key, nonce) pair under
 * GCM (M3); and the key was derived deterministically from the room key, so
 * collisions accumulated across sessions instead of being confined to one
 * call (M5). A per-sender key plus a mandatory per-call `call_id` removes
 * both, and the sender's 16 random bytes make a collision between two
 * participants a 2^-128 event rather than a 2^-32 one.
 *
 * Field ownership:
 *
 *   call_id      16 B  per call, from the initiator; all-zero is refused
 *   key_version   2 B  K_room generation, fixed for the life of the call
 *   sender_salt  16 B  drawn once per call object, never re-drawn mid-call
 *   idbind       32 B  the sender's Ed25519 public key, or 32 zero bytes
 *                      when the call runs unsigned (--no-sign)
 *
 * All multi-byte integers here are big-endian, like every other field on the
 * media wire. Note that identity/key_schedule.h is little-endian and is NOT
 * reused by this path.
 *
 * Nothing in this module is allowed to change mid-call. The send context is
 * drawn before any encrypting thread starts and is then immutable, which is
 * what lets the counters run without a lock: there is no re-derivation to
 * interleave with them.
 */
#ifndef FEAR_MEDIA_KEYS_H
#define FEAR_MEDIA_KEYS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Derived media key length (AES-256-GCM). */
#define MK_KEY_BYTES 32

/** Per-sender salt announced in HELLO. */
#define MK_SALT_BYTES 16

/** Per-call identifier; binds every key so a recording cannot replay into another call. */
#define MK_CALLID_BYTES 16

/** Sender tag on the wire, carved out of the old 8-byte sequence field. */
#define MK_SID_BYTES 3

/** HELLO authentication tag. */
#define MK_MAC_BYTES 16

/** Identity binding length (an Ed25519 public key, or zeros when unsigned). */
#define MK_IDBIND_BYTES 32

/**
 * Largest forward jump a replay window may accept in one step. Without it a
 * single forged packet at a huge counter advances the window and permanently
 * silences the real sender.
 */
#define MK_MAX_CTR_JUMP 16384

/** Domain separation strings. */
#define MK_CTX_V2       "fear.media.v2"
#define MK_SID_CTX      "fear.media.sid.v2"
#define MK_HELLO_CTX    "fear.media.hello.v2"

/**
 * Counter domain, not media type: `stream` names which sequence counter the
 * key protects. audio_call has one counter carrying both audio and stats;
 * video_call has an audio counter and a video counter, the latter carrying
 * both fragments and stats. Two packet types on one counter share one key
 * safely because the counter never repeats. Two counters under one key would
 * be a nonce collision, so a new counter always needs a new stream id.
 */
typedef enum {
    MK_STREAM_AUDIO = 0,
    MK_STREAM_VIDEO = 1
} mk_stream_t;

/**
 * Parse a call_id from 32 hex characters.
 *
 * Rejects an all-zero value for the same reason the derivations do: it is
 * what a path that forgot to plumb the field through would produce, and
 * accepting it would silently drop the cross-call replay barrier.
 *
 * @return 0 on success, -1 on a malformed or all-zero value
 */
int mk_call_id_parse(const char *hex, uint8_t out[MK_CALLID_BYTES]);

/**
 * Derive the HELLO authentication key for a call. Computable before any
 * packet is parsed, so an off-path attacker cannot inject a handshake.
 *
 * @return 0 on success, -1 on bad arguments, all-zero call_id, or hash failure
 */
int mk_hello_key(const uint8_t k_call[MK_KEY_BYTES],
                 const uint8_t call_id[MK_CALLID_BYTES],
                 uint8_t out_key[MK_KEY_BYTES]);

/**
 * Derive one sender's media key for one counter domain.
 *
 * Used both ways: with our own salt and identity to get our send key, and
 * with a peer's announced salt and identity to get the key we decrypt that
 * peer with.
 *
 * @param idbind  the sender's Ed25519 public key, or 32 zero bytes if unsigned
 * @return 0 on success, -1 on bad arguments, all-zero call_id, or hash failure
 */
int mk_derive_sender(const uint8_t k_call[MK_KEY_BYTES],
                     mk_stream_t stream,
                     uint16_t key_version,
                     const uint8_t call_id[MK_CALLID_BYTES],
                     const uint8_t sender_salt[MK_SALT_BYTES],
                     const uint8_t idbind[MK_IDBIND_BYTES],
                     uint8_t out_key[MK_KEY_BYTES]);

/**
 * Compute a sender's wire tag. One tag identifies a participant across audio,
 * video and stats, so it deliberately does not depend on `stream`.
 *
 * BLAKE2b cannot produce a 3-byte digest (its minimum is 16 and the length is
 * bound into the parameter block), so this computes 16 bytes and truncates.
 * Any port must truncate the same way or the tags diverge.
 *
 * @return 0 on success, -1 on bad arguments, all-zero call_id, or hash failure
 */
int mk_sender_id(const uint8_t k_call[MK_KEY_BYTES],
                 const uint8_t call_id[MK_CALLID_BYTES],
                 const uint8_t sender_salt[MK_SALT_BYTES],
                 const uint8_t idbind[MK_IDBIND_BYTES],
                 uint8_t out_sid[MK_SID_BYTES]);

/**
 * Authenticate a HELLO body under the call's HELLO key.
 *
 * @param hello      the HELLO bytes excluding the trailing MAC
 * @param hello_len  their length
 * @return 0 on success, -1 on bad arguments or hash failure
 */
int mk_hello_mac(const uint8_t hello_key[MK_KEY_BYTES],
                 const uint8_t *hello, size_t hello_len,
                 uint8_t out_mac[MK_MAC_BYTES]);

/**
 * Verify a HELLO MAC in constant time.
 * @return 0 if the MAC is correct, -1 otherwise
 */
int mk_hello_mac_verify(const uint8_t hello_key[MK_KEY_BYTES],
                        const uint8_t *hello, size_t hello_len,
                        const uint8_t mac[MK_MAC_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_MEDIA_KEYS_H */
