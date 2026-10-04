/**
 * @file media_packet.c
 * @brief Media packet framing (see media_packet.h).
 */
#include "media_packet.h"

#include <sodium.h>
#include <string.h>

#define OFF_TYPE    0
#define OFF_SID     1
#define OFF_COUNTER 4
#define COUNTER_BYTES 5

static void wr_counter(uint8_t *p, uint64_t v) {
    for (int i = 0; i < COUNTER_BYTES; i++) {
        p[i] = (uint8_t)((v >> (8 * (COUNTER_BYTES - 1 - i))) & 0xFF);
    }
}

static uint64_t rd_counter(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < COUNTER_BYTES; i++) v = (v << 8) | p[i];
    return v;
}

/** nonce = SID(3) || four zero bytes || counter(5) */
static void make_nonce(uint8_t out[crypto_aead_aes256gcm_NPUBBYTES],
                       const uint8_t sid[MK_SID_BYTES], uint64_t counter) {
    memset(out, 0, crypto_aead_aes256gcm_NPUBBYTES);
    memcpy(out, sid, MK_SID_BYTES);
    wr_counter(out + MK_SID_BYTES + 4, counter);
}

int mp_encrypt(uint8_t type,
               const uint8_t sid[MK_SID_BYTES],
               uint64_t counter,
               const uint8_t key[MK_KEY_BYTES],
               const uint8_t *plain, size_t plain_len,
               uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!sid || !key || !out || !out_len) return -1;
    if (plain_len > 0 && !plain) return -1;
    if (counter > MP_MAX_COUNTER) return -1;

    const size_t total = MP_HEADER_BYTES + plain_len + MP_TAG_BYTES;
    if (out_cap < total) return -1;

    out[OFF_TYPE] = type;
    memcpy(out + OFF_SID, sid, MK_SID_BYTES);
    wr_counter(out + OFF_COUNTER, counter);

    uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    make_nonce(nonce, sid, counter);

    unsigned long long clen = 0;
    /* The header is the associated data, so type and counter are covered by
     * the tag even though they travel in the clear. */
    int rc = crypto_aead_aes256gcm_encrypt(
        out + MP_HEADER_BYTES, &clen,
        plain, plain_len,
        out, MP_HEADER_BYTES,
        NULL, nonce, key);
    sodium_memzero(nonce, sizeof nonce);
    if (rc != 0) return -1;

    *out_len = MP_HEADER_BYTES + (size_t)clen;
    return 0;
}

int mp_peek(const uint8_t *pkt, size_t pkt_len,
            uint8_t *out_type, uint8_t out_sid[MK_SID_BYTES],
            uint64_t *out_counter) {
    if (!pkt) return -1;
    if (pkt_len < MP_HEADER_BYTES + MP_TAG_BYTES) return -1;

    if (out_type)    *out_type = pkt[OFF_TYPE];
    if (out_sid)     memcpy(out_sid, pkt + OFF_SID, MK_SID_BYTES);
    if (out_counter) *out_counter = rd_counter(pkt + OFF_COUNTER);
    return 0;
}

int mp_decrypt(const uint8_t *pkt, size_t pkt_len,
               const uint8_t key[MK_KEY_BYTES],
               uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!pkt || !key || !out || !out_len) return -1;
    if (pkt_len < MP_HEADER_BYTES + MP_TAG_BYTES) return -1;

    const size_t clen = pkt_len - MP_HEADER_BYTES;
    /* Bound the output before decrypting: libsodium writes clen - tag bytes
     * into `out` and touches the buffer even when the tag turns out to be
     * wrong, so checking afterwards would be too late. This is the same
     * failure the audit found in the stats path (C1). */
    if (clen < MP_TAG_BYTES || clen - MP_TAG_BYTES > out_cap) return -1;

    uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    make_nonce(nonce, pkt + OFF_SID, rd_counter(pkt + OFF_COUNTER));

    unsigned long long mlen = 0;
    int rc = crypto_aead_aes256gcm_decrypt(
        out, &mlen, NULL,
        pkt + MP_HEADER_BYTES, clen,
        pkt, MP_HEADER_BYTES,
        nonce, key);
    sodium_memzero(nonce, sizeof nonce);
    if (rc != 0) return -1;

    *out_len = (size_t)mlen;
    return 0;
}
