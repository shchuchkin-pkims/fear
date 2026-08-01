/**
 * @file chat_frame.c
 * @brief Sealing a chat payload under the room key schedule (see chat_frame.h).
 */
#include "chat_frame.h"

#include <sodium.h>
#include <string.h>
#include <time.h>

/** K_room generation used when the caller has not been told otherwise. */
#define CF_KEY_VERSION 0

const char *cf_strerror(cf_status_t st) {
    switch (st) {
        case CF_OK:            return "ok";
        case CF_ERR_ARGS:      return "bad arguments";
        case CF_ERR_SPACE:     return "output buffer too small";
        case CF_ERR_TOO_SHORT: return "sealed payload has no header";
        case CF_ERR_VERSION:   return "unknown K_room generation";
        case CF_ERR_EPOCH:     return "epoch too far from ours";
        case CF_ERR_DERIVE:    return "epoch key derivation failed";
        case CF_ERR_AUTH:      return "authentication failed";
    }
    return "unknown";
}

/**
 * Additional data: what the server routes on, then the six bytes that name
 * the key. Built into the caller's buffer to keep this allocation-free -
 * every chat frame goes through here.
 *
 * @return the length written, or 0 if it does not fit
 */
static size_t cf_ad(const char *room, const char *name,
                    const uint8_t hdr[KS_HEADER_BYTES],
                    uint8_t *out, size_t out_cap) {
    size_t room_len = strlen(room);
    size_t name_len = strlen(name);
    if (room_len > 0xFFFF || name_len > 0xFFFF) return 0;

    size_t need = 2 + room_len + 2 + name_len + KS_HEADER_BYTES;
    if (need > out_cap) return 0;

    /* Little endian, matching wr_u16 in the console client and
     * Common.writeUInt16 on Android. The AD has to be byte-identical on both
     * platforms or nothing decrypts across them. */
    uint8_t *w = out;
    *w++ = (uint8_t)(room_len & 0xFF);
    *w++ = (uint8_t)((room_len >> 8) & 0xFF);
    memcpy(w, room, room_len); w += room_len;
    *w++ = (uint8_t)(name_len & 0xFF);
    *w++ = (uint8_t)((name_len >> 8) & 0xFF);
    memcpy(w, name, name_len); w += name_len;
    memcpy(w, hdr, KS_HEADER_BYTES);
    return need;
}

/** Room and name are bounded by the frame format; 1 KiB covers both twice. */
#define CF_AD_MAX 1024

cf_status_t cf_seal_at(const cf_key_t *key,
                       const char *room, const char *name,
                       const uint8_t *plain, size_t plen,
                       const uint8_t nonce[CF_NONCE_BYTES],
                       uint32_t epoch,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!key || !room || !name || !nonce || !out || !out_len) return CF_ERR_ARGS;
    uint16_t key_version = key->version;
    const uint8_t *k_room = key->key;
    if (plen > 0 && !plain) return CF_ERR_ARGS;
    if (out_cap < plen + CF_OVERHEAD_BYTES) return CF_ERR_SPACE;

    uint8_t hdr[KS_HEADER_BYTES];
    ks_write_header(hdr, key_version, epoch);

    uint8_t ad[CF_AD_MAX];
    size_t ad_len = cf_ad(room, name, hdr, ad, sizeof ad);
    if (ad_len == 0) return CF_ERR_ARGS;

    uint8_t k_epoch[KS_KEY_BYTES];
    if (ks_derive_epoch_key(k_room, key_version, epoch, k_epoch) != 0) {
        return CF_ERR_DERIVE;
    }

    unsigned long long clen = 0;
    int rc = crypto_aead_aes256gcm_encrypt(out + KS_HEADER_BYTES, &clen,
                                           plain, (unsigned long long)plen,
                                           ad, (unsigned long long)ad_len,
                                           NULL, nonce, k_epoch);
    sodium_memzero(k_epoch, sizeof k_epoch);
    if (rc != 0) return CF_ERR_AUTH;

    memcpy(out, hdr, KS_HEADER_BYTES);
    *out_len = KS_HEADER_BYTES + (size_t)clen;
    return CF_OK;
}

cf_status_t cf_seal(const cf_key_t *key,
                    const char *room, const char *name,
                    const uint8_t *plain, size_t plen,
                    const uint8_t nonce[CF_NONCE_BYTES],
                    uint8_t *out, size_t out_cap, size_t *out_len) {
    uint32_t epoch = ks_epoch_from_unix((uint64_t)time(NULL));
    return cf_seal_at(key, room, name, plain, plen, nonce,
                      epoch, out, out_cap, out_len);
}

cf_status_t cf_open_at(const cf_key_t *keys, size_t nkeys,
                       const char *room, const char *name,
                       const uint8_t *sealed, size_t sealed_len,
                       const uint8_t nonce[CF_NONCE_BYTES],
                       uint32_t local_epoch,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!keys || nkeys == 0 || !room || !name || !sealed || !nonce ||
        !out || !out_len) {
        return CF_ERR_ARGS;
    }
    if (sealed_len < KS_HEADER_BYTES + CF_TAG_BYTES) return CF_ERR_TOO_SHORT;

    size_t body_len = sealed_len - KS_HEADER_BYTES;
    if (out_cap < body_len - CF_TAG_BYTES) return CF_ERR_SPACE;

    uint16_t version = 0;
    uint32_t epoch = 0;
    ks_read_header(sealed, &version, &epoch);

    /* Both checks come before the derivation on purpose: an attacker who can
     * name a generation or an epoch should not be able to make us derive
     * anything at all. */
    const uint8_t *k_room = NULL;
    for (size_t i = 0; i < nkeys; i++) {
        if (keys[i].version == version) { k_room = keys[i].key; break; }
    }
    if (!k_room) return CF_ERR_VERSION;
    if (!ks_epoch_acceptable(epoch, local_epoch)) return CF_ERR_EPOCH;

    uint8_t ad[CF_AD_MAX];
    size_t ad_len = cf_ad(room, name, sealed, ad, sizeof ad);
    if (ad_len == 0) return CF_ERR_ARGS;

    uint8_t k_epoch[KS_KEY_BYTES];
    if (ks_derive_epoch_key(k_room, version, epoch, k_epoch) != 0) {
        return CF_ERR_DERIVE;
    }

    unsigned long long plen = 0;
    int rc = crypto_aead_aes256gcm_decrypt(out, &plen, NULL,
                                           sealed + KS_HEADER_BYTES,
                                           (unsigned long long)body_len,
                                           ad, (unsigned long long)ad_len,
                                           nonce, k_epoch);
    sodium_memzero(k_epoch, sizeof k_epoch);
    if (rc != 0) return CF_ERR_AUTH;

    *out_len = (size_t)plen;
    return CF_OK;
}

cf_status_t cf_open(const cf_key_t *keys, size_t nkeys,
                    const char *room, const char *name,
                    const uint8_t *sealed, size_t sealed_len,
                    const uint8_t nonce[CF_NONCE_BYTES],
                    uint8_t *out, size_t out_cap, size_t *out_len) {
    uint32_t local = ks_epoch_from_unix((uint64_t)time(NULL));
    return cf_open_at(keys, nkeys, room, name, sealed, sealed_len, nonce,
                      local, out, out_cap, out_len);
}
