/**
 * @file call_invite.h
 * @brief Call invitation payload (Phase C, step 4).
 *
 * A call needs one value that every participant shares and that no
 * recording from an earlier call can supply: the `call_id`. Every media key
 * is bound to it, so replaying a captured HELLO and its media into a later
 * call fails at the first derivation.
 *
 * There was nowhere to put that value. Calls are set up entirely by hand
 * today - one side listens, the other types an address and a port into a
 * dialog - and the chat channel carries no call signalling at all. Deriving
 * the value from the room key instead would make it identical for every
 * call in that room, which is precisely the replay window it exists to
 * close.
 *
 * So the initiator draws a `call_id` and announces it on the chat channel,
 * which is already end-to-end encrypted under the room key. The relay
 * cannot read it, cannot forge one, and every room member receives it -
 * which is also what makes this work for group calls rather than only for
 * two parties.
 *
 * Payload, inside the chat message envelope:
 *
 *    off size field
 *      0    1  version, 0x01
 *      1    1  media flags: 0x01 audio, 0x02 video
 *      2   16  call_id
 *     18    2  port, big endian, 0 when the call goes through the relay
 *     20    1  host length, 0 when the call goes through the relay
 *     21    n  host, UTF-8, no NUL
 *
 * The host and port are a hint for a direct connection and are allowed to
 * be absent; the call_id is not. A receiver that cannot use the hint can
 * still join through the relay, and a group call over the hub uses no hint
 * at all.
 */
#ifndef FEAR_CALL_INVITE_H
#define FEAR_CALL_INVITE_H

#include <stddef.h>
#include <stdint.h>

#include "media_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CI_VERSION       0x01

#define CI_FLAG_AUDIO    0x01
#define CI_FLAG_VIDEO    0x02
/** Bits nobody has defined yet; must be zero on the wire. */
#define CI_FLAG_RESERVED 0xFC

/** Longest host a hint may carry. */
#define CI_MAX_HOST      255

/** Bytes before the host field. */
#define CI_HEADER_BYTES  21

/** Largest possible payload. */
#define CI_MAX_BYTES     (CI_HEADER_BYTES + CI_MAX_HOST)

typedef enum {
    CI_OK = 0,
    CI_ERR_ARGS,
    CI_ERR_TOO_SHORT,
    CI_ERR_VERSION,
    CI_ERR_RESERVED,
    CI_ERR_CALLID,    /**< all-zero: the sender never plumbed the field through */
    CI_ERR_LENGTH,    /**< declared host length disagrees with the payload */
    CI_ERR_HOST       /**< host contains bytes that have no business in a hostname */
} ci_status_t;

typedef struct {
    uint8_t  flags;
    uint8_t  call_id[MK_CALLID_BYTES];
    uint16_t port;
    /** NUL-terminated; empty when the invite carries no direct hint. */
    char     host[CI_MAX_HOST + 1];
} ci_invite_t;

/**
 * Serialize an invite.
 * @param out_len receives the payload length on success
 */
ci_status_t ci_build(const ci_invite_t *in,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Parse and validate an invite. Nothing is written to `out` unless CI_OK is
 * returned.
 *
 * The host is checked rather than trusted: it arrives from another party
 * and ends up in a connect call and in log lines, so anything outside the
 * character set a hostname or an IPv4/IPv6 literal can contain is refused
 * here instead of being sanitised at each use.
 */
ci_status_t ci_parse(const uint8_t *buf, size_t len, ci_invite_t *out);

/** Human-readable reason, for logs. Never NULL. */
const char *ci_strerror(ci_status_t st);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_CALL_INVITE_H */
