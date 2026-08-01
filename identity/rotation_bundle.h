/**
 * @file rotation_bundle.h
 * @brief The message that carries a rotation to every member (Phase C).
 *
 * rotation.h seals K_room for one recipient. This is the envelope that
 * carries one such entry per member and lets each of them find their own.
 *
 * Layout, all multi-byte integers little-endian to match the rest of the
 * chat wire:
 *
 *    off size field
 *      0    1  0x01, format version
 *      1    2  key_version being installed
 *      3   32  sender's Ed25519 identity key
 *     35    2  entry count
 *     37  136  entry, repeated: [recipient_pk(32)][nonce(24)][ct(80)]
 *
 * The room is not on the wire. It is the room the frame arrived in, and it
 * is bound into every entry's plaintext by rotation_binding - so a bundle
 * lifted into another room does not open, and there is no room name here
 * for anyone to disagree about.
 *
 * Nor is there anything to hide: every entry is addressed to a public key
 * and sealed to it, so the bundle is safe to broadcast. What it does reveal
 * is the membership - who holds a key in this room - which the roster
 * already tells anyone connected to the server.
 *
 * Whether the sender is *allowed* to rotate is not decided here. This
 * module reports who sealed the bundle; room_keys.h decides whether that is
 * the member the room expects, and the caller refuses one that is not.
 */
#ifndef FEAR_ROTATION_BUNDLE_H
#define FEAR_ROTATION_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#include "rotation.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RB_FORMAT_VERSION 0x01

/** Bytes before the first entry. */
#define RB_HEADER_BYTES 37

/** Members one bundle may address. Matches the server's client cap. */
#define RB_MAX_ENTRIES 100

/** One value per rejection, so a dropped bundle can say why. */
typedef enum {
    RB_OK = 0,
    RB_ERR_ARGS,        /**< caller passed something impossible */
    RB_ERR_SPACE,       /**< output buffer too small */
    RB_ERR_TOO_SHORT,   /**< cannot even contain a header */
    RB_ERR_FORMAT,      /**< format version we do not speak */
    RB_ERR_LENGTH,      /**< entry count disagrees with the length */
    RB_ERR_TOO_MANY,    /**< more entries than we will look at */
    RB_ERR_SEAL,        /**< sealing an entry failed */
    RB_ERR_NOT_FOR_US,  /**< no entry addressed to this recipient */
    RB_ERR_OPEN         /**< our entry did not open */
} rb_status_t;

const char *rb_strerror(rb_status_t st);

/** What a receiver learns before opening anything. */
typedef struct {
    uint16_t       key_version;
    const uint8_t *sender_pk;     /**< into the caller's buffer */
    uint16_t       entry_count;
    const uint8_t *entries;       /**< into the caller's buffer */
} rb_view_t;

/** Bytes a bundle for `n` recipients occupies. */
size_t rb_size(size_t n);

/**
 * Build a bundle installing `new_k_room` as generation `new_version`.
 *
 * Every recipient gets an entry, including the sender: a member that cannot
 * open its own bundle has rotated itself out of the room.
 *
 * @return RB_OK on success
 */
rb_status_t rb_build(const char *room_id, uint16_t new_version,
                     const uint8_t new_k_room[ROTATION_KEY_BYTES],
                     const uint8_t sender_sk[64],
                     const uint8_t sender_pk[32],
                     const uint8_t (*recipient_pks)[32], size_t nrecipients,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Read the header and locate the entries, opening nothing.
 *
 * On success every pointer in `out` lies inside `buf`.
 */
rb_status_t rb_parse(const uint8_t *buf, size_t len, rb_view_t *out);

/**
 * Find the entry addressed to us and recover K_room from it.
 *
 * The entry is authenticated to `view->sender_pk` and bound to this room and
 * this generation, so an entry moved between bundles, rooms, versions or
 * recipients does not open.
 */
rb_status_t rb_open_for(const rb_view_t *view, const char *room_id,
                        const uint8_t recipient_sk[64],
                        const uint8_t recipient_pk[32],
                        uint8_t out_k_room[ROTATION_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_ROTATION_BUNDLE_H */
