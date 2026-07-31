/**
 * @file media_packet.h
 * @brief Media packet framing for group calls (Phase C, step 5).
 *
 * The pre-group packet was [type(1)][seq(8)] with the nonce built from a
 * 4-byte prefix learned in HELLO plus that sequence. That prefix is what
 * cannot survive three participants: a receiver caches exactly one, so the
 * last HELLO wins and every other peer's traffic becomes undecryptable.
 *
 * The same nine header bytes are repartitioned instead:
 *
 *    off size field
 *      0    1  packet type, unchanged values
 *      1    3  SID, the sender tag (see mk_sender_id)
 *      4    5  counter, big endian, per sender and counter domain
 *      9   ..  AES-256-GCM ciphertext and its 16-byte tag
 *
 *    nonce = SID(3) || 0x00 00 00 00 || counter(5)
 *    AAD   = the nine cleartext header bytes
 *
 * Zero added bytes per packet, so every buffer size in the tree still
 * holds. The counter is 2^40 rather than 2^64, which at the highest rate
 * this codebase produces - video fragments at the top quality preset, about
 * 156 packets a second - is roughly 223 years, so exhaustion inside a call
 * cannot happen and no recovery path is needed for it.
 *
 * Two changes that are not just about group calls:
 *
 * - The key is per sender, so a receiver picks it by SID instead of holding
 *   one key for whoever spoke last. Two senders can both start their
 *   counters at zero without ever sharing a (key, nonce) pair.
 * - The header is authenticated. It used to be cleartext and unbound, so a
 *   captured packet could have its type byte flipped between audio and
 *   stats: same key, same counter, and the receiver would route the
 *   plaintext to the wrong parser. Binding the header as AAD closes that.
 */
#ifndef FEAR_MEDIA_PACKET_H
#define FEAR_MEDIA_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "media_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Cleartext header: [type(1)][SID(3)][counter(5)]. */
#define MP_HEADER_BYTES 9

/** AES-256-GCM tag. */
#define MP_TAG_BYTES 16

/** Largest counter the 5-byte field can carry. */
#define MP_MAX_COUNTER 0xFFFFFFFFFFULL

/**
 * Frame and encrypt one media packet.
 *
 * @param type    packet type byte, e.g. audio or stats
 * @param sid     our own sender tag
 * @param counter our counter for this stream; must never repeat under `key`
 * @param key     our send key for this stream (mk_derive_sender)
 * @param out     buffer of at least MP_HEADER_BYTES + plain_len + MP_TAG_BYTES
 * @return 0 on success, -1 on bad arguments or an out-of-range counter
 */
int mp_encrypt(uint8_t type,
               const uint8_t sid[MK_SID_BYTES],
               uint64_t counter,
               const uint8_t key[MK_KEY_BYTES],
               const uint8_t *plain, size_t plain_len,
               uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Read the header of an arriving packet without decrypting it.
 *
 * A receiver needs the SID to choose which key to try, so this is
 * deliberately separate from mp_decrypt. Nothing here is trusted: the
 * header is authenticated only once mp_decrypt succeeds.
 *
 * @return 0 on success, -1 if the packet cannot hold a header and a tag
 */
int mp_peek(const uint8_t *pkt, size_t pkt_len,
            uint8_t *out_type, uint8_t out_sid[MK_SID_BYTES],
            uint64_t *out_counter);

/**
 * Decrypt one media packet under a candidate key.
 *
 * The nine header bytes are authenticated as associated data, so a packet
 * whose type or counter was altered fails here rather than being routed to
 * the wrong parser.
 *
 * @return 0 on success, -1 on any failure
 */
int mp_decrypt(const uint8_t *pkt, size_t pkt_len,
               const uint8_t key[MK_KEY_BYTES],
               uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_MEDIA_PACKET_H */
