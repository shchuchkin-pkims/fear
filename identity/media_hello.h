/**
 * @file media_hello.h
 * @brief HELLO2 handshake codec for group calls (Phase C).
 *
 * One packet announces everything a peer needs to derive our media keys:
 * the call we are in, the K_room generation, our own random salt and,
 * optionally, our identity. Receivers need nothing from us beyond this.
 *
 * Layout, type 0x7E version 0x04, all multi-byte integers big-endian:
 *
 *    off size field
 *      0    1  0x7E
 *      1    1  0x04
 *      2    2  total length: 78 unsigned, 174 signed
 *      4    1  flags: VIDEO 0x01, AUDIO 0x02, IDENTITY 0x04,
 *              0x08 reserved (sender-key wrapping), 0x10..0x80 reserved
 *      5    1  reserved, must be zero
 *      6    2  key_version
 *      8   16  call_id
 *     24   16  sender_salt
 *     40    2  width   (zero unless VIDEO)
 *     42    2  height  (zero unless VIDEO)
 *     44    1  fps     (zero unless VIDEO)
 *     45    1  reserved, must be zero
 *     46   16  display name, NUL-padded, may be entirely NUL
 *     62   32  Ed25519 public key      only when IDENTITY
 *     94   64  Ed25519 signature over [0,94)  only when IDENTITY
 *  len-16   16  MAC over [0, len-16)
 *
 * The display name says who the sender calls themselves, so a call can put a
 * person's name under their picture instead of six hex digits of their SID.
 * It is a label and not an identity: the MAC only proves a room member sent
 * it, and any room member can forge another member's unsigned announcement -
 * that is a property of the shared call key, not of this field. Where it
 * matters, the fingerprint printed on a signed HELLO is what identifies a
 * participant, and the name inside a signed one is covered by the signature.
 *
 * Control characters are refused rather than sanitised. The name reaches
 * terminals and text renderers, and a parser that quietly rewrites its input
 * is harder to reason about than one that rejects it.
 *
 * The video parameters are always present and zeroed for audio-only calls,
 * so a receiver dispatches on flags and never on length. The old wire had
 * four length tiers and no length field at all, which is why every existing
 * parser silently tolerates trailing bytes.
 *
 * Two authentications, doing different jobs. The MAC is keyed by K_hello,
 * which every room member holds and nobody outside does: it keeps off-path
 * attackers and the relay out of the handshake entirely, and it binds the
 * packet to one call. The optional signature binds the salt to an identity
 * so trust-on-first-use can run per participant. A member of the room can
 * always forge another member's unsigned HELLO - media is authenticated at
 * room granularity, not participant granularity, and that is a property of
 * the shared call key rather than of this format.
 *
 * Parse order matters and is enforced: the MAC is checked before any field
 * is trusted or any state is touched.
 */
#ifndef FEAR_MEDIA_HELLO_H
#define FEAR_MEDIA_HELLO_H

#include <stddef.h>
#include <stdint.h>

#include "media_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MH_TYPE            0x7E
#define MH_VERSION         0x04

/** The packet type of the pre-group HELLO, kept only to recognise old peers. */
#define MH_LEGACY_TYPE     0x7F

#define MH_SIZE_BASE       78
#define MH_SIZE_SIGNED     174

/** Display name field width. Not NUL-terminated when it is exactly full. */
#define MH_NAME_BYTES      16

#define MH_FLAG_VIDEO      0x01
#define MH_FLAG_AUDIO      0x02
#define MH_FLAG_IDENTITY   0x04
/** Reserved for per-sender key wrapping; must be zero on the wire today. */
#define MH_FLAG_RESERVED   0xF8

#define MH_PK_BYTES        32
#define MH_SIG_BYTES       64

/** One value per rejection, so a dropped packet can say why. */
typedef enum {
    MH_OK = 0,
    MH_ERR_ARGS,          /**< caller passed something impossible */
    MH_ERR_TOO_SHORT,     /**< cannot even contain a MAC */
    MH_ERR_TYPE,          /**< not a HELLO2 */
    MH_ERR_LEGACY_PEER,   /**< a pre-group HELLO: the peer needs updating */
    MH_ERR_MAC,           /**< wrong call, or forged */
    MH_ERR_VERSION,
    MH_ERR_LENGTH,        /**< length field or packet size disagrees with flags */
    MH_ERR_RESERVED,      /**< a reserved bit or byte was set */
    MH_ERR_CALLID,
    MH_ERR_NAME,          /**< display name has control characters or bad padding */        /**< all-zero call_id */
    MH_ERR_SIGNATURE      /**< IDENTITY set but the signature does not verify */
} mh_status_t;

/** The decoded announcement. */
typedef struct {
    uint8_t  flags;
    uint16_t key_version;
    uint8_t  call_id[MK_CALLID_BYTES];
    uint8_t  sender_salt[MK_SALT_BYTES];
    uint16_t width;
    uint16_t height;
    uint8_t  fps;
    /**
     * What the sender calls themselves, NUL-padded and always
     * NUL-terminated here even when the wire field is full. Empty when the
     * sender announced none.
     */
    char     name[MH_NAME_BYTES + 1];
    /** Valid only when flags & MH_FLAG_IDENTITY. */
    uint8_t  pk[MH_PK_BYTES];
} mh_hello_t;

/** Wire size implied by a flag set: MH_SIZE_SIGNED or MH_SIZE_BASE. */
size_t mh_size(uint8_t flags);

/**
 * Serialize and authenticate a HELLO.
 *
 * @param in          fields to send; video parameters are ignored and zeroed
 *                    unless MH_FLAG_VIDEO is set
 * @param hello_key   K_hello for this call
 * @param identity_sk 64-byte Ed25519 secret key, required iff MH_FLAG_IDENTITY
 * @param out         buffer of at least mh_size(in->flags) bytes
 * @param out_cap     its capacity
 * @param out_len     receives the number of bytes written
 */
mh_status_t mh_build(const mh_hello_t *in,
                     const uint8_t hello_key[MK_KEY_BYTES],
                     const uint8_t *identity_sk,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Verify and decode a HELLO. Nothing is written to `out` unless MH_OK is
 * returned, and the MAC is verified before any field is examined.
 *
 * Returns MH_ERR_LEGACY_PEER for a packet that is byte-plausible as a
 * pre-group HELLO, so the caller can tell the user their peer is too old
 * instead of leaving the call silently dead.
 */
mh_status_t mh_parse(const uint8_t *buf, size_t len,
                     const uint8_t hello_key[MK_KEY_BYTES],
                     mh_hello_t *out);

/** Human-readable reason, for logs. Never NULL. */
const char *mh_strerror(mh_status_t st);

#ifdef __cplusplus
}
#endif

#endif /* FEAR_MEDIA_HELLO_H */
