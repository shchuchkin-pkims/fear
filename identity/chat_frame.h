/**
 * @file chat_frame.h
 * @brief Sealing a chat payload under the room key schedule (Phase C).
 *
 * A chat frame's ciphertext field is
 *
 *     [key_version(2)][epoch(4)][AES-256-GCM ciphertext || tag]
 *
 * encrypted not under K_room but under the epoch key derived from it:
 *
 *     K_epoch = BLAKE2b(key = K_room, "fear.epoch.v1" || version || epoch)
 *
 * Every member derives the same K_epoch from the same hour; nothing is
 * exchanged to agree on it, and K_epoch is never stored.
 *
 * The six header bytes are in the clear and are bound into the additional
 * data along with the room and sender the server routes on. So a relay can
 * read them for nothing - it has to, to route - and cannot change them
 * without the AEAD failing.
 *
 * They sit in front of the ciphertext rather than in a field of their own
 * because the server reads the message type and the ciphertext length at
 * fixed offsets and treats the ciphertext itself as opaque. Nothing in the
 * server changes, which is right twice over: it does not need to understand
 * the key schedule, and it must not be able to act on it.
 *
 * What this gives and what it does not: keys are separated per hour and
 * K_epoch never reaches storage. It is not forward secrecy on its own -
 * anyone holding K_room derives every epoch. That needs rotation on a
 * membership change and the old K_room actually destroyed.
 *
 * key_version names the K_room generation. It is still zero everywhere until
 * rotation bundles land, but the plumbing takes a set of generations now
 * rather than one key, because the moment rotation exists a receiver has to
 * be able to read the messages that were already on their way.
 */
#ifndef FEAR_CHAT_FRAME_H
#define FEAR_CHAT_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "key_schedule.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AES-256-GCM nonce, in bytes. */
#define CF_NONCE_BYTES 12

/** AES-256-GCM authentication tag, in bytes. */
#define CF_TAG_BYTES 16

/** Bytes a sealed payload adds to the plaintext. */
#define CF_OVERHEAD_BYTES (KS_HEADER_BYTES + CF_TAG_BYTES)

/**
 * One generation of K_room.
 *
 * Sealing takes exactly one - the current generation, never an old one.
 * Opening takes a small set, because a rotation does not stop the messages
 * already in flight under the generation it replaces: they arrive after it
 * and would be refused by a receiver that had already forgotten how to read
 * them. Two is enough for that, and holding more would be keeping keys alive
 * for no reason anyone can point at.
 */
typedef struct {
    uint16_t version;
    uint8_t  key[KS_KEY_BYTES];
} cf_key_t;

/** Generations a receiver may hold at once. */
#define CF_MAX_KEYS 2

/** One value per rejection, so a dropped frame can say why. */
typedef enum {
    CF_OK = 0,
    CF_ERR_ARGS,        /**< caller passed something impossible */
    CF_ERR_SPACE,       /**< output buffer too small */
    CF_ERR_TOO_SHORT,   /**< sealed payload cannot even contain a header */
    CF_ERR_VERSION,     /**< K_room generation we do not have */
    CF_ERR_EPOCH,       /**< epoch too far from ours to be honest */
    CF_ERR_DERIVE,      /**< epoch key derivation failed */
    CF_ERR_AUTH         /**< AEAD rejected it: wrong key, or tampered */
} cf_status_t;

/** Human-readable form of a status, for logs. */
const char *cf_strerror(cf_status_t st);

/**
 * Seal a payload for a named epoch. Deterministic: the same inputs give the
 * same bytes, which is what lets a test pin the format across platforms.
 *
 * @param out_cap must be at least plen + CF_OVERHEAD_BYTES
 */
cf_status_t cf_seal_at(const cf_key_t *key,
                       const char *room, const char *name,
                       const uint8_t *plain, size_t plen,
                       const uint8_t nonce[CF_NONCE_BYTES],
                       uint32_t epoch,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/** Seal for the current hour and the current K_room generation. */
cf_status_t cf_seal(const cf_key_t *key,
                    const char *room, const char *name,
                    const uint8_t *plain, size_t plen,
                    const uint8_t nonce[CF_NONCE_BYTES],
                    uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Open a sealed payload.
 *
 * The epoch is checked against `local_epoch` before anything is derived:
 * otherwise anyone able to name an epoch could make us derive an unbounded
 * number of keys, and a message from days ago is a replay however well it
 * authenticates.
 */
cf_status_t cf_open_at(const cf_key_t *keys, size_t nkeys,
                       const char *room, const char *name,
                       const uint8_t *sealed, size_t sealed_len,
                       const uint8_t nonce[CF_NONCE_BYTES],
                       uint32_t local_epoch,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/** Open, taking the local epoch from the clock. */
cf_status_t cf_open(const cf_key_t *keys, size_t nkeys,
                    const char *room, const char *name,
                    const uint8_t *sealed, size_t sealed_len,
                    const uint8_t nonce[CF_NONCE_BYTES],
                    uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_CHAT_FRAME_H */
