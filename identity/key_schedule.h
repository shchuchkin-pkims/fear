/**
 * @file key_schedule.h
 * @brief Room key schedule for F.E.A.R. (Phase C, architecture §5).
 *
 * Two levels:
 *
 *   K_room    32 bytes, generated when the room is created, distributed
 *             over X25519 to each member, stored locally, never sent in
 *             the clear and never known to the server. It changes only on
 *             a membership change (join / leave), and each generation gets
 *             a monotonically increasing `key_version`.
 *
 *   K_epoch   derived, never stored:
 *                 K_epoch = BLAKE2b(key = K_room,
 *                                   data = "fear.epoch.v1" || version || epoch,
 *                                   out  = 32)
 *             where `epoch` is the number of whole hours since the UNIX
 *             epoch. Every member derives the same K_epoch independently
 *             from the clock; nothing is exchanged.
 *
 * The wire header carries [key_version(2)][epoch(4)], little endian, so a
 * receiver knows which K_room generation and which hour to derive for.
 *
 * Note on the `version` input: architecture §5 writes the derivation as
 * HKDF(K_room_v, "fear.epoch.v1" || N). We additionally bind `key_version`
 * into the KDF input. It costs nothing and it turns a header/key mismatch
 * (stale header claiming v1 while the sender used v2) into a clean
 * authentication failure instead of a silent derivation of the wrong key.
 */
#ifndef FEAR_KEY_SCHEDULE_H
#define FEAR_KEY_SCHEDULE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes in K_room and in every derived K_epoch. */
#define KS_KEY_BYTES 32

/** Length of one epoch, in seconds (architecture §5: one hour). */
#define KS_EPOCH_SECONDS 3600u

/** Domain separation string for the epoch derivation. */
#define KS_EPOCH_CTX "fear.epoch.v1"

/** Wire header: [key_version(2)][epoch(4)], little endian. */
#define KS_HEADER_BYTES 6

/**
 * How far the epoch in a received header may drift from the local one and
 * still be accepted: one epoch either way. Covers modest clock skew and a
 * message that crosses the hour boundary in flight, without opening a wide
 * window for replaying old traffic.
 */
#define KS_EPOCH_SKEW 1u

/**
 * Epoch number for a UNIX timestamp (whole hours since the epoch).
 * Saturates instead of wrapping so a bogus far-future clock cannot alias
 * onto a valid epoch.
 */
uint32_t ks_epoch_from_unix(uint64_t unix_seconds);

/**
 * Derive K_epoch for (K_room, key_version, epoch).
 *
 * @param k_room       32-byte room master key of generation `key_version`
 * @param key_version  K_room generation from the wire header
 * @param epoch        epoch number from the wire header
 * @param out_key      receives the 32-byte epoch key
 * @return 0 on success, -1 on bad arguments or hash failure
 */
int ks_derive_epoch_key(const uint8_t k_room[KS_KEY_BYTES],
                        uint16_t key_version,
                        uint32_t epoch,
                        uint8_t out_key[KS_KEY_BYTES]);

/**
 * Whether a header epoch is close enough to the local epoch to be used.
 * @return 1 if acceptable, 0 otherwise
 */
int ks_epoch_acceptable(uint32_t header_epoch, uint32_t local_epoch);

/** Serialize [key_version(2)][epoch(4)] little endian into `out`. */
void ks_write_header(uint8_t out[KS_HEADER_BYTES],
                     uint16_t key_version, uint32_t epoch);

/** Parse [key_version(2)][epoch(4)] little endian from `in`. */
void ks_read_header(const uint8_t in[KS_HEADER_BYTES],
                    uint16_t *key_version, uint32_t *epoch);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_KEY_SCHEDULE_H */
