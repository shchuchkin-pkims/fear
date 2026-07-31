/**
 * @file media_hello.c
 * @brief HELLO2 handshake codec (see media_hello.h).
 */
#include "media_hello.h"

#include <sodium.h>
#include <string.h>

/* Field offsets, straight from the layout in the header. */
#define OFF_TYPE        0
#define OFF_VERSION     1
#define OFF_LENGTH      2
#define OFF_FLAGS       4
#define OFF_RSVD1       5
#define OFF_KEYVER      6
#define OFF_CALLID      8
#define OFF_SALT       24
#define OFF_WIDTH      40
#define OFF_HEIGHT     42
#define OFF_FPS        44
#define OFF_RSVD2      45
#define OFF_NAME       46
#define OFF_PK         62
#define OFF_SIG        94
/** The signature covers everything before it, the name included. */
#define SIGNED_RANGE   94

static void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

size_t mh_size(uint8_t flags) {
    return (flags & MH_FLAG_IDENTITY) ? MH_SIZE_SIGNED : MH_SIZE_BASE;
}

const char *mh_strerror(mh_status_t st) {
    switch (st) {
        case MH_OK:              return "ok";
        case MH_ERR_ARGS:        return "bad arguments";
        case MH_ERR_TOO_SHORT:   return "packet too short";
        case MH_ERR_TYPE:        return "not a HELLO2 packet";
        case MH_ERR_LEGACY_PEER: return "peer speaks the pre-group HELLO and must be updated";
        case MH_ERR_MAC:         return "MAC failed: wrong call key or forged";
        case MH_ERR_VERSION:     return "unsupported HELLO2 version";
        case MH_ERR_LENGTH:      return "length disagrees with flags";
        case MH_ERR_RESERVED:    return "reserved bits set";
        case MH_ERR_CALLID:      return "call_id is all zero";
        case MH_ERR_NAME:        return "display name is malformed";
        case MH_ERR_SIGNATURE:   return "identity signature failed";
    }
    return "unknown";
}

mh_status_t mh_build(const mh_hello_t *in,
                     const uint8_t hello_key[MK_KEY_BYTES],
                     const uint8_t *identity_sk,
                     uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!in || !hello_key || !out || !out_len) return MH_ERR_ARGS;
    if (in->flags & MH_FLAG_RESERVED) return MH_ERR_RESERVED;
    if ((in->flags & MH_FLAG_IDENTITY) && !identity_sk) return MH_ERR_ARGS;
    if (sodium_is_zero(in->call_id, MK_CALLID_BYTES)) return MH_ERR_CALLID;

    const size_t total = mh_size(in->flags);
    if (out_cap < total) return MH_ERR_ARGS;

    memset(out, 0, total);
    out[OFF_TYPE]    = MH_TYPE;
    out[OFF_VERSION] = MH_VERSION;
    wr_be16(out + OFF_LENGTH, (uint16_t)total);
    out[OFF_FLAGS]   = in->flags;
    wr_be16(out + OFF_KEYVER, in->key_version);
    memcpy(out + OFF_CALLID, in->call_id, MK_CALLID_BYTES);
    memcpy(out + OFF_SALT, in->sender_salt, MK_SALT_BYTES);

    /* Truncated rather than refused: a long name is a display problem, and
     * failing to announce ourselves at all over one would be worse. The
     * buffer is already zeroed, so short names are NUL-padded. */
    {
        size_t n = 0;
        while (n < MH_NAME_BYTES && in->name[n] != '\0') n++;
        memcpy(out + OFF_NAME, in->name, n);
    }

    /* Video parameters are structurally present but meaningless without the
     * flag, so they are zeroed rather than sent as stale values. */
    if (in->flags & MH_FLAG_VIDEO) {
        wr_be16(out + OFF_WIDTH, in->width);
        wr_be16(out + OFF_HEIGHT, in->height);
        out[OFF_FPS] = in->fps;
    }

    if (in->flags & MH_FLAG_IDENTITY) {
        /* The public key is taken from the secret key rather than from the
         * caller: an sk and a mismatched pk would produce a HELLO that only
         * fails later, at the peer. */
        memcpy(out + OFF_PK, identity_sk + 32, MH_PK_BYTES);
        if (crypto_sign_detached(out + OFF_SIG, NULL,
                                 out, SIGNED_RANGE, identity_sk) != 0) {
            sodium_memzero(out, total);
            return MH_ERR_SIGNATURE;
        }
    }

    if (mk_hello_mac(hello_key, out, total - MK_MAC_BYTES,
                     out + total - MK_MAC_BYTES) != 0) {
        sodium_memzero(out, total);
        return MH_ERR_ARGS;
    }

    *out_len = total;
    return MH_OK;
}

mh_status_t mh_parse(const uint8_t *buf, size_t len,
                     const uint8_t hello_key[MK_KEY_BYTES],
                     mh_hello_t *out) {
    if (!buf || !hello_key || !out) return MH_ERR_ARGS;

    /* Recognising an old peer costs nothing and touches no state. */
    if (len > 0 && buf[OFF_TYPE] == MH_LEGACY_TYPE) return MH_ERR_LEGACY_PEER;
    if (len > 0 && buf[OFF_TYPE] != MH_TYPE) return MH_ERR_TYPE;
    if (len < MK_MAC_BYTES + 1) return MH_ERR_TOO_SHORT;
    /* Bound the work before hashing anything an attacker sized. */
    if (len > MH_SIZE_SIGNED) return MH_ERR_LENGTH;

    /* The MAC gates everything: no field below is trusted, and no state
     * anywhere is touched, until it verifies. It covers the length and flags
     * bytes too, so those cannot be tampered with to steer the parse. */
    if (mk_hello_mac_verify(hello_key, buf, len - MK_MAC_BYTES,
                            buf + len - MK_MAC_BYTES) != 0) {
        return MH_ERR_MAC;
    }

    if (buf[OFF_VERSION] != MH_VERSION) return MH_ERR_VERSION;

    const uint8_t flags = buf[OFF_FLAGS];
    if (flags & MH_FLAG_RESERVED) return MH_ERR_RESERVED;
    if (buf[OFF_RSVD1] != 0 || buf[OFF_RSVD2] != 0) return MH_ERR_RESERVED;

    /* No tolerance: the declared length, the received length and the length
     * implied by the flags must all agree. */
    if (len != mh_size(flags)) return MH_ERR_LENGTH;
    if (rd_be16(buf + OFF_LENGTH) != (uint16_t)len) return MH_ERR_LENGTH;

    if (sodium_is_zero(buf + OFF_CALLID, MK_CALLID_BYTES)) return MH_ERR_CALLID;

    /* The name ends up in terminals and text renderers, so control
     * characters are refused rather than stripped, and everything after the
     * first NUL has to be NUL: padding is not a place to hide bytes that a
     * careless consumer might read past the terminator. UTF-8 is allowed
     * through - a name is not required to be English. */
    {
        int ended = 0;
        for (size_t i = 0; i < MH_NAME_BYTES; i++) {
            uint8_t ch = buf[OFF_NAME + i];
            if (ended) {
                if (ch != 0) return MH_ERR_NAME;
                continue;
            }
            if (ch == 0) { ended = 1; continue; }
            if (ch < 0x20 || ch == 0x7F) return MH_ERR_NAME;
        }
    }

    if (flags & MH_FLAG_IDENTITY) {
        if (crypto_sign_verify_detached(buf + OFF_SIG, buf, SIGNED_RANGE,
                                        buf + OFF_PK) != 0) {
            return MH_ERR_SIGNATURE;
        }
    }

    memset(out, 0, sizeof *out);
    out->flags       = flags;
    out->key_version = rd_be16(buf + OFF_KEYVER);
    memcpy(out->call_id, buf + OFF_CALLID, MK_CALLID_BYTES);
    memcpy(out->sender_salt, buf + OFF_SALT, MK_SALT_BYTES);
    memcpy(out->name, buf + OFF_NAME, MH_NAME_BYTES);
    out->name[MH_NAME_BYTES] = '\0';
    if (flags & MH_FLAG_VIDEO) {
        out->width  = rd_be16(buf + OFF_WIDTH);
        out->height = rd_be16(buf + OFF_HEIGHT);
        out->fps    = buf[OFF_FPS];
    }
    if (flags & MH_FLAG_IDENTITY) {
        memcpy(out->pk, buf + OFF_PK, MH_PK_BYTES);
    }
    return MH_OK;
}
