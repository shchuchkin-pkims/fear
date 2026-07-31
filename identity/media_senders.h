/**
 * @file media_senders.h
 * @brief Per-sender key slots and replay windows for group calls (Phase C).
 *
 * A call has one shared key and N senders, each encrypting under a key
 * derived from its own announcement (see media_keys.h). This module is the
 * bookkeeping that turns that into a working receiver: which senders exist,
 * which key decrypts an arriving packet, and whether that packet is fresh.
 *
 * Design points that are not obvious and are each protecting against
 * something specific:
 *
 * - **Slots are never evicted to make room.** A full table refuses new
 *   installs instead. Eviction under pressure would let any room member
 *   push out a participant they dislike by installing salts, and it would
 *   silently discard that participant's replay state.
 *
 * - **A retired slot leaves a tombstone** holding its salt and replay
 *   high-water mark. Reinstalling that salt resumes the old window rather
 *   than starting from zero, so a recorded stream cannot be replayed back
 *   into a slot that was released and reused.
 *
 * - **Candidates for a SID are walked oldest-install first**, and at most
 *   two live slots may share one. A 3-byte tag collides for real at these
 *   sizes, so collisions must be survivable; but ordering by recency would
 *   let an attacker who grinds a colliding salt jump the queue and mute the
 *   participant who was there first.
 *
 * - **The replay window refuses large forward jumps.** Accepting any
 *   counter that decrypts means one forged packet at a huge value advances
 *   the window past everything real, permanently silencing the sender.
 *   That is a live bug in the shipped desktop code, not a hypothetical.
 */
#ifndef FEAR_MEDIA_SENDERS_H
#define FEAR_MEDIA_SENDERS_H

#include <stddef.h>
#include <stdint.h>

#include "media_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Key slots. Matches MAX_HUB_CLIENTS, so the transport cannot outrun the table. */
#define MS_MAX_SLOTS 32

/** Live slots allowed to share one 3-byte SID. */
#define MS_SID_CAP 2

/** Counter domains a sender can use (audio, video). */
#define MS_STREAMS 2

/** Sliding replay window width, in packets. */
#define MS_WINDOW_BITS 64

typedef enum {
    MS_OK = 0,
    MS_ERR_ARGS,
    MS_ERR_FULL,        /**< no free slot; the table refuses rather than evicts */
    MS_ERR_SID_CAP,     /**< too many live slots already answer to this SID */
    MS_ERR_SELF,        /**< this is our own salt coming back at us */
    MS_ERR_NOT_FOUND
} ms_status_t;

/** Result of offering a packet counter to a slot. */
typedef enum {
    MS_FRESH = 0,       /**< accepted and recorded */
    MS_REPLAY,          /**< already seen, or too old for the window */
    MS_JUMP             /**< implausibly far ahead: refused, window untouched */
} ms_seq_verdict_t;

typedef struct {
    uint64_t max_seq;
    uint64_t bitmap;    /**< bit i set means (max_seq - i) was seen */
    int      started;
} ms_window_t;

typedef struct {
    int      used;
    uint8_t  sid[MK_SID_BYTES];
    uint8_t  salt[MK_SALT_BYTES];
    uint8_t  idbind[MK_IDBIND_BYTES];
    uint16_t key_version;
    uint8_t  key[MS_STREAMS][MK_KEY_BYTES];
    uint32_t install_order;
    ms_window_t win[MS_STREAMS];
} ms_slot_t;

/** What survives a slot being released, so its counters cannot be rewound. */
typedef struct {
    int         used;
    uint8_t     salt[MK_SALT_BYTES];
    uint8_t     idbind[MK_IDBIND_BYTES];
    ms_window_t win[MS_STREAMS];
} ms_tomb_t;

typedef struct {
    uint8_t   k_call[MK_KEY_BYTES];
    uint8_t   call_id[MK_CALLID_BYTES];
    uint8_t   own_salt[MK_SALT_BYTES];
    int       have_own_salt;
    uint32_t  next_order;
    ms_slot_t slots[MS_MAX_SLOTS];
    ms_tomb_t tombs[MS_MAX_SLOTS];
} ms_table_t;

/**
 * Initialise a table for one call. `own_salt` may be NULL, but passing it
 * lets the table reject our own salt echoed back at us, which would
 * otherwise install a slot whose keys are identical to our send keys.
 */
ms_status_t ms_init(ms_table_t *t,
                    const uint8_t k_call[MK_KEY_BYTES],
                    const uint8_t call_id[MK_CALLID_BYTES],
                    const uint8_t own_salt[MK_SALT_BYTES]);

/** Wipe every key and salt held by the table. */
void ms_clear(ms_table_t *t);

/**
 * Install a sender announced by a verified HELLO, or return the existing
 * slot if this salt is already present (installing twice is a no-op, which
 * is what makes a repeated HELLO harmless).
 *
 * @param idbind  the sender's Ed25519 pk, or 32 zero bytes when unsigned
 * @param out_idx receives the slot index on MS_OK
 */
ms_status_t ms_install(ms_table_t *t,
                       const uint8_t salt[MK_SALT_BYTES],
                       const uint8_t idbind[MK_IDBIND_BYTES],
                       uint16_t key_version,
                       int *out_idx);

/** Release a slot, leaving a tombstone that preserves its replay state. */
ms_status_t ms_retire(ms_table_t *t, int idx);

/** Number of live slots. */
int ms_count(const ms_table_t *t);

/**
 * Find candidate slots for a wire SID, oldest install first.
 *
 * A 3-byte tag collides, so a receiver must be prepared to try more than
 * one key. Returns how many indices were written to `out_idx`.
 *
 * @param out_idx array of at least MS_SID_CAP entries
 */
int ms_find_by_sid(const ms_table_t *t,
                   const uint8_t sid[MK_SID_BYTES],
                   int *out_idx);

/** The decryption key for a slot and counter domain, or NULL. */
const uint8_t *ms_key(const ms_table_t *t, int idx, mk_stream_t stream);

/**
 * Offer a counter to a slot's replay window.
 *
 * Call this only after the packet has been authenticated: a forged counter
 * that is allowed to move the window is exactly the denial of service this
 * guards against. On MS_FRESH the window is updated; otherwise it is not.
 */
ms_seq_verdict_t ms_accept_seq(ms_table_t *t, int idx,
                               mk_stream_t stream, uint64_t seq);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_MEDIA_SENDERS_H */
