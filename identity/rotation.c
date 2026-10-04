/**
 * @file rotation.c
 * @brief Room key rotation bundles (see rotation.h, architecture §5).
 */
#include "rotation.h"

#include <sodium.h>
#include <string.h>

/* Sealed plaintext layout: K_room(32) || binding(32). */
#define ROT_PT_BYTES 64

int rotation_binding(const char *room_id, uint16_t new_version,
                     const uint8_t sender_pk[32],
                     const uint8_t recipient_pk[32],
                     uint8_t out_binding[32]) {
    if (!room_id || !sender_pk || !recipient_pk || !out_binding) return -1;
    const size_t room_len = strlen(room_id);
    if (room_len > ROTATION_MAX_ROOM_ID) return -1;

    static const char ctx[] = ROTATION_BINDING_CTX;
    const uint8_t ver_le[2] = { (uint8_t)(new_version & 0xFF),
                                (uint8_t)((new_version >> 8) & 0xFF) };

    /* Streaming hash: the room id is variable length, so there is no fixed
     * buffer to size wrongly. Fields are concatenated in a fixed order and
     * the only variable-length one is last-but-three, which is fine because
     * every following field has a fixed width. */
    crypto_generichash_state st;
    if (crypto_generichash_init(&st, NULL, 0, 32) != 0) return -1;
    crypto_generichash_update(&st, (const uint8_t *)ctx, sizeof(ctx) - 1);
    crypto_generichash_update(&st, (const uint8_t *)room_id, room_len);
    crypto_generichash_update(&st, ver_le, sizeof ver_le);
    crypto_generichash_update(&st, sender_pk, 32);
    crypto_generichash_update(&st, recipient_pk, 32);
    return (crypto_generichash_final(&st, out_binding, 32) == 0) ? 0 : -1;
}

/** Convert the ed25519 identity pair into the X25519 keys crypto_box needs. */
static int to_curve(const uint8_t ed_sk[64], const uint8_t ed_pk[32],
                    uint8_t x_sk[32], uint8_t x_pk[32]) {
    if (ed_sk && crypto_sign_ed25519_sk_to_curve25519(x_sk, ed_sk) != 0) return -1;
    if (ed_pk && crypto_sign_ed25519_pk_to_curve25519(x_pk, ed_pk) != 0) return -1;
    return 0;
}

int rotation_seal_with_nonce(const char *room_id, uint16_t new_version,
                             const uint8_t new_k_room[ROTATION_KEY_BYTES],
                             const uint8_t sender_sk[64],
                             const uint8_t sender_pk[32],
                             const uint8_t recipient_pk[32],
                             const uint8_t nonce[ROTATION_NONCE_BYTES],
                             uint8_t out_entry[ROTATION_ENTRY_BYTES]) {
    if (!room_id || !new_k_room || !sender_sk || !sender_pk ||
        !recipient_pk || !nonce || !out_entry) return -1;

    uint8_t pt[ROT_PT_BYTES];
    memcpy(pt, new_k_room, ROTATION_KEY_BYTES);
    if (rotation_binding(room_id, new_version, sender_pk, recipient_pk,
                         pt + ROTATION_KEY_BYTES) != 0) {
        sodium_memzero(pt, sizeof pt);
        return -1;
    }

    uint8_t x_sk[32], x_pk[32];
    if (to_curve(sender_sk, recipient_pk, x_sk, x_pk) != 0) {
        sodium_memzero(pt, sizeof pt);
        sodium_memzero(x_sk, sizeof x_sk);
        return -1;
    }

    uint8_t ct[ROTATION_CT_BYTES];
    int rc = crypto_box_easy(ct, pt, sizeof pt, nonce, x_pk, x_sk);
    sodium_memzero(pt, sizeof pt);
    sodium_memzero(x_sk, sizeof x_sk);
    if (rc != 0) return -1;

    memcpy(out_entry, recipient_pk, 32);
    memcpy(out_entry + 32, nonce, ROTATION_NONCE_BYTES);
    memcpy(out_entry + 32 + ROTATION_NONCE_BYTES, ct, sizeof ct);
    return 0;
}

int rotation_seal(const char *room_id, uint16_t new_version,
                  const uint8_t new_k_room[ROTATION_KEY_BYTES],
                  const uint8_t sender_sk[64],
                  const uint8_t sender_pk[32],
                  const uint8_t recipient_pk[32],
                  uint8_t out_entry[ROTATION_ENTRY_BYTES]) {
    uint8_t nonce[ROTATION_NONCE_BYTES];
    randombytes_buf(nonce, sizeof nonce);
    return rotation_seal_with_nonce(room_id, new_version, new_k_room,
                                    sender_sk, sender_pk, recipient_pk,
                                    nonce, out_entry);
}

int rotation_open(const char *room_id, uint16_t new_version,
                  const uint8_t recipient_sk[64],
                  const uint8_t recipient_pk[32],
                  const uint8_t sender_pk[32],
                  const uint8_t entry[ROTATION_ENTRY_BYTES],
                  uint8_t out_k_room[ROTATION_KEY_BYTES]) {
    if (!room_id || !recipient_sk || !recipient_pk || !sender_pk ||
        !entry || !out_k_room) return -1;

    /* Is this entry even addressed to us? */
    if (sodium_memcmp(entry, recipient_pk, 32) != 0) return -1;

    const uint8_t *nonce = entry + 32;
    const uint8_t *ct    = entry + 32 + ROTATION_NONCE_BYTES;

    uint8_t x_sk[32], x_pk[32];
    if (to_curve(recipient_sk, sender_pk, x_sk, x_pk) != 0) {
        sodium_memzero(x_sk, sizeof x_sk);
        return -1;
    }

    uint8_t pt[ROT_PT_BYTES];
    int rc = crypto_box_open_easy(pt, ct, ROTATION_CT_BYTES, nonce, x_pk, x_sk);
    sodium_memzero(x_sk, sizeof x_sk);
    if (rc != 0) {
        sodium_memzero(pt, sizeof pt);
        return -1;   /* wrong sender, wrong recipient key, or tampered */
    }

    /* The box only proves who sealed it; the binding proves what for. */
    uint8_t expect[32];
    if (rotation_binding(room_id, new_version, sender_pk, recipient_pk, expect) != 0) {
        sodium_memzero(pt, sizeof pt);
        return -1;
    }
    if (sodium_memcmp(pt + ROTATION_KEY_BYTES, expect, 32) != 0) {
        sodium_memzero(pt, sizeof pt);
        return -1;   /* replayed into another room / version */
    }

    memcpy(out_k_room, pt, ROTATION_KEY_BYTES);
    sodium_memzero(pt, sizeof pt);
    return 0;
}
