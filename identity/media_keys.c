/**
 * @file media_keys.c
 * @brief Per-direction media keys (see media_keys.h, audit M3/M5).
 */
#include "media_keys.h"

#include <sodium.h>
#include <string.h>

int mk_salt_combine(const uint8_t master[MK_KEY_BYTES],
                    const uint8_t half_a[MK_SALT_BYTES],
                    const uint8_t half_b[MK_SALT_BYTES],
                    uint8_t out_salt[MK_SALT_BYTES]) {
    if (!master || !half_a || !half_b || !out_salt) return -1;

    /* Order by memcmp so the fold is commutative: the two ends do not have
     * to agree on who is "a" and who is "b". */
    const int cmp = memcmp(half_a, half_b, MK_SALT_BYTES);
    const uint8_t *lo = (cmp <= 0) ? half_a : half_b;
    const uint8_t *hi = (cmp <= 0) ? half_b : half_a;

    static const char ctx[] = MK_SALT_CTX;
    const size_t ctx_len = sizeof(ctx) - 1;

    uint8_t info[sizeof(ctx) - 1 + 2 * MK_SALT_BYTES];
    memcpy(info, ctx, ctx_len);
    memcpy(info + ctx_len, lo, MK_SALT_BYTES);
    memcpy(info + ctx_len + MK_SALT_BYTES, hi, MK_SALT_BYTES);

    int rc = crypto_generichash(out_salt, MK_SALT_BYTES,
                                info, sizeof(info),
                                master, MK_KEY_BYTES);
    sodium_memzero(info, sizeof(info));
    return (rc == 0) ? 0 : -1;
}

int mk_role_from_halves(const uint8_t local_half[MK_SALT_BYTES],
                        const uint8_t peer_half[MK_SALT_BYTES],
                        int *out_is_caller) {
    if (!local_half || !peer_half || !out_is_caller) return -1;

    const int cmp = memcmp(local_half, peer_half, MK_SALT_BYTES);
    if (cmp == 0) return -1;   /* reflected HELLO - see media_keys.h */

    *out_is_caller = (cmp < 0) ? 1 : 0;
    return 0;
}

int mk_derive(const uint8_t master[MK_KEY_BYTES],
              mk_stream_t stream, mk_dir_t dir,
              const uint8_t salt[MK_SALT_BYTES],
              uint8_t out_key[MK_KEY_BYTES]) {
    if (!master || !salt || !out_key) return -1;
    if (stream != MK_STREAM_AUDIO && stream != MK_STREAM_VIDEO) return -1;
    if (dir != MK_DIR_CALLER_TO_CALLEE && dir != MK_DIR_CALLEE_TO_CALLER) return -1;

    static const char ctx[] = MK_CTX;
    const size_t ctx_len = sizeof(ctx) - 1;

    uint8_t info[sizeof(ctx) - 1 + 2 + MK_SALT_BYTES];
    memcpy(info, ctx, ctx_len);
    info[ctx_len]     = (uint8_t)stream;
    info[ctx_len + 1] = (uint8_t)dir;
    memcpy(info + ctx_len + 2, salt, MK_SALT_BYTES);

    int rc = crypto_generichash(out_key, MK_KEY_BYTES,
                                info, sizeof(info),
                                master, MK_KEY_BYTES);
    sodium_memzero(info, sizeof(info));
    return (rc == 0) ? 0 : -1;
}

int mk_derive_pair(const uint8_t master[MK_KEY_BYTES],
                   mk_stream_t stream, int is_caller,
                   const uint8_t salt[MK_SALT_BYTES],
                   uint8_t out_send[MK_KEY_BYTES],
                   uint8_t out_recv[MK_KEY_BYTES]) {
    if (!out_send || !out_recv) return -1;

    const mk_dir_t send_dir = is_caller ? MK_DIR_CALLER_TO_CALLEE
                                        : MK_DIR_CALLEE_TO_CALLER;
    const mk_dir_t recv_dir = is_caller ? MK_DIR_CALLEE_TO_CALLER
                                        : MK_DIR_CALLER_TO_CALLEE;

    if (mk_derive(master, stream, send_dir, salt, out_send) != 0) return -1;
    if (mk_derive(master, stream, recv_dir, salt, out_recv) != 0) {
        sodium_memzero(out_send, MK_KEY_BYTES);
        return -1;
    }
    return 0;
}
