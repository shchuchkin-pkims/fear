/**
 * @file media_keys.c
 * @brief Sender-rooted media keys (see media_keys.h).
 */
#include "media_keys.h"

#include <sodium.h>
#include <stddef.h>
#include <string.h>

/* BLAKE2b's minimum output; a SID is the first MK_SID_BYTES of one of these. */
#define MK_SID_FULL_BYTES 16

/* A call_id of all zeros means nobody set one. Refusing it keeps the
 * cross-call replay barrier from being silently disabled by a caller that
 * forgot to plumb the field through. */
static int callid_is_zero(const uint8_t call_id[MK_CALLID_BYTES]) {
    return sodium_is_zero(call_id, MK_CALLID_BYTES);
}

int mk_hello_key(const uint8_t k_call[MK_KEY_BYTES],
                 const uint8_t call_id[MK_CALLID_BYTES],
                 uint8_t out_key[MK_KEY_BYTES]) {
    if (!k_call || !call_id || !out_key) return -1;
    if (callid_is_zero(call_id)) return -1;

    static const char ctx[] = MK_HELLO_CTX;
    const size_t ctx_len = sizeof(ctx) - 1;

    uint8_t info[sizeof(ctx) - 1 + MK_CALLID_BYTES];
    memcpy(info, ctx, ctx_len);
    memcpy(info + ctx_len, call_id, MK_CALLID_BYTES);

    int rc = crypto_generichash(out_key, MK_KEY_BYTES,
                                info, sizeof(info),
                                k_call, MK_KEY_BYTES);
    sodium_memzero(info, sizeof(info));
    return (rc == 0) ? 0 : -1;
}

int mk_derive_sender(const uint8_t k_call[MK_KEY_BYTES],
                     mk_stream_t stream,
                     uint16_t key_version,
                     const uint8_t call_id[MK_CALLID_BYTES],
                     const uint8_t sender_salt[MK_SALT_BYTES],
                     const uint8_t idbind[MK_IDBIND_BYTES],
                     uint8_t out_key[MK_KEY_BYTES]) {
    if (!k_call || !call_id || !sender_salt || !idbind || !out_key) return -1;
    if (stream != MK_STREAM_AUDIO && stream != MK_STREAM_VIDEO) return -1;
    if (callid_is_zero(call_id)) return -1;

    static const char ctx[] = MK_CTX_V2;
    const size_t ctx_len = sizeof(ctx) - 1;

    /* ctx || stream(1) || key_version(2 BE) || call_id || salt || idbind */
    uint8_t info[sizeof(ctx) - 1 + 1 + 2 + MK_CALLID_BYTES
                 + MK_SALT_BYTES + MK_IDBIND_BYTES];
    size_t o = ctx_len;
    memcpy(info, ctx, ctx_len);
    info[o++] = (uint8_t)stream;
    info[o++] = (uint8_t)((key_version >> 8) & 0xFF);   /* big endian */
    info[o++] = (uint8_t)(key_version & 0xFF);
    memcpy(info + o, call_id, MK_CALLID_BYTES);       o += MK_CALLID_BYTES;
    memcpy(info + o, sender_salt, MK_SALT_BYTES);     o += MK_SALT_BYTES;
    memcpy(info + o, idbind, MK_IDBIND_BYTES);

    int rc = crypto_generichash(out_key, MK_KEY_BYTES,
                                info, sizeof(info),
                                k_call, MK_KEY_BYTES);
    sodium_memzero(info, sizeof(info));
    return (rc == 0) ? 0 : -1;
}

int mk_sender_id(const uint8_t k_call[MK_KEY_BYTES],
                 const uint8_t call_id[MK_CALLID_BYTES],
                 const uint8_t sender_salt[MK_SALT_BYTES],
                 const uint8_t idbind[MK_IDBIND_BYTES],
                 uint8_t out_sid[MK_SID_BYTES]) {
    if (!k_call || !call_id || !sender_salt || !idbind || !out_sid) return -1;
    if (callid_is_zero(call_id)) return -1;

    static const char ctx[] = MK_SID_CTX;
    const size_t ctx_len = sizeof(ctx) - 1;

    /* No `stream`: one tag identifies a participant across every stream. */
    uint8_t info[sizeof(ctx) - 1 + MK_CALLID_BYTES + MK_SALT_BYTES + MK_IDBIND_BYTES];
    size_t o = ctx_len;
    memcpy(info, ctx, ctx_len);
    memcpy(info + o, call_id, MK_CALLID_BYTES);       o += MK_CALLID_BYTES;
    memcpy(info + o, sender_salt, MK_SALT_BYTES);     o += MK_SALT_BYTES;
    memcpy(info + o, idbind, MK_IDBIND_BYTES);

    uint8_t full[MK_SID_FULL_BYTES];
    int rc = crypto_generichash(full, sizeof(full),
                                info, sizeof(info),
                                k_call, MK_KEY_BYTES);
    sodium_memzero(info, sizeof(info));
    if (rc != 0) return -1;

    memcpy(out_sid, full, MK_SID_BYTES);
    sodium_memzero(full, sizeof(full));
    return 0;
}

int mk_hello_mac(const uint8_t hello_key[MK_KEY_BYTES],
                 const uint8_t *hello, size_t hello_len,
                 uint8_t out_mac[MK_MAC_BYTES]) {
    if (!hello_key || !out_mac) return -1;
    if (hello_len > 0 && !hello) return -1;

    return (crypto_generichash(out_mac, MK_MAC_BYTES,
                               hello, hello_len,
                               hello_key, MK_KEY_BYTES) == 0) ? 0 : -1;
}

int mk_hello_mac_verify(const uint8_t hello_key[MK_KEY_BYTES],
                        const uint8_t *hello, size_t hello_len,
                        const uint8_t mac[MK_MAC_BYTES]) {
    if (!mac) return -1;

    uint8_t expect[MK_MAC_BYTES];
    if (mk_hello_mac(hello_key, hello, hello_len, expect) != 0) return -1;

    /* Constant time: a byte-at-a-time compare would leak the MAC one byte
     * per forgery attempt, and the attacker controls how often it retries. */
    int rc = sodium_memcmp(expect, mac, MK_MAC_BYTES);
    sodium_memzero(expect, sizeof(expect));
    return (rc == 0) ? 0 : -1;
}
