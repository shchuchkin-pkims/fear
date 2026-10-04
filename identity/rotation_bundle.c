/**
 * @file rotation_bundle.c
 * @brief The rotation envelope (see rotation_bundle.h).
 */
#include "rotation_bundle.h"

#include <sodium.h>
#include <string.h>

const char *rb_strerror(rb_status_t st) {
    switch (st) {
        case RB_OK:            return "ok";
        case RB_ERR_ARGS:      return "bad arguments";
        case RB_ERR_SPACE:     return "output buffer too small";
        case RB_ERR_TOO_SHORT: return "bundle has no header";
        case RB_ERR_FORMAT:    return "unsupported bundle format";
        case RB_ERR_LENGTH:    return "entry count disagrees with the length";
        case RB_ERR_TOO_MANY:  return "more entries than we will look at";
        case RB_ERR_SEAL:      return "sealing an entry failed";
        case RB_ERR_NOT_FOR_US: return "no entry addressed to us";
        case RB_ERR_OPEN:      return "our entry did not open";
    }
    return "unknown";
}

size_t rb_size(size_t n) {
    return RB_HEADER_BYTES + n * ROTATION_ENTRY_BYTES;
}

static void wr_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static uint16_t rd_u16le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

rb_status_t rb_build(const char *room_id, uint16_t new_version,
                     const uint8_t new_k_room[ROTATION_KEY_BYTES],
                     const uint8_t sender_sk[64],
                     const uint8_t sender_pk[32],
                     const uint8_t (*recipient_pks)[32], size_t nrecipients,
                     uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!room_id || !new_k_room || !sender_sk || !sender_pk ||
        !recipient_pks || !out || !out_len) {
        return RB_ERR_ARGS;
    }
    if (nrecipients == 0) return RB_ERR_ARGS;
    if (nrecipients > RB_MAX_ENTRIES) return RB_ERR_TOO_MANY;

    size_t need = rb_size(nrecipients);
    if (out_cap < need) return RB_ERR_SPACE;

    out[0] = RB_FORMAT_VERSION;
    wr_u16le(out + 1, new_version);
    memcpy(out + 3, sender_pk, 32);
    wr_u16le(out + 35, (uint16_t)nrecipients);

    uint8_t *w = out + RB_HEADER_BYTES;
    for (size_t i = 0; i < nrecipients; i++) {
        if (rotation_seal(room_id, new_version, new_k_room,
                          sender_sk, sender_pk, recipient_pks[i], w) != 0) {
            /* A half-built bundle is worse than none: it would install the
             * new key for some members and leave the rest unable to read
             * anything. */
            sodium_memzero(out, need);
            return RB_ERR_SEAL;
        }
        w += ROTATION_ENTRY_BYTES;
    }

    *out_len = need;
    return RB_OK;
}

rb_status_t rb_parse(const uint8_t *buf, size_t len, rb_view_t *out) {
    if (!buf || !out) return RB_ERR_ARGS;
    if (len < RB_HEADER_BYTES) return RB_ERR_TOO_SHORT;
    if (buf[0] != RB_FORMAT_VERSION) return RB_ERR_FORMAT;

    uint16_t count = rd_u16le(buf + 35);
    if (count == 0) return RB_ERR_LENGTH;
    if (count > RB_MAX_ENTRIES) return RB_ERR_TOO_MANY;

    /* The declared count and the actual length have to agree exactly. A
     * bundle with room for fewer entries than it claims would have us read
     * past the end; one with more has something in it we are not looking at. */
    if (len != rb_size(count)) return RB_ERR_LENGTH;

    out->key_version = rd_u16le(buf + 1);
    out->sender_pk   = buf + 3;
    out->entry_count = count;
    out->entries     = buf + RB_HEADER_BYTES;
    return RB_OK;
}

rb_status_t rb_open_for(const rb_view_t *view, const char *room_id,
                        const uint8_t recipient_sk[64],
                        const uint8_t recipient_pk[32],
                        uint8_t out_k_room[ROTATION_KEY_BYTES]) {
    if (!view || !view->entries || !view->sender_pk || !room_id ||
        !recipient_sk || !recipient_pk || !out_k_room) {
        return RB_ERR_ARGS;
    }

    for (uint16_t i = 0; i < view->entry_count; i++) {
        const uint8_t *entry = view->entries + (size_t)i * ROTATION_ENTRY_BYTES;

        /* The address is the first 32 bytes, in the clear. Comparing it first
         * is only a shortcut: rotation_open would refuse an entry meant for
         * somebody else anyway, since the recipient is bound into what it
         * authenticates. */
        if (sodium_memcmp(entry, recipient_pk, 32) != 0) continue;

        if (rotation_open(room_id, view->key_version, recipient_sk,
                          recipient_pk, view->sender_pk, entry,
                          out_k_room) != 0) {
            return RB_ERR_OPEN;
        }
        return RB_OK;
    }
    return RB_ERR_NOT_FOR_US;
}
