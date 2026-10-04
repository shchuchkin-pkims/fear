/**
 * @file key_schedule.c
 * @brief Room key schedule implementation (see key_schedule.h, architecture §5).
 */
#include "key_schedule.h"

#include <sodium.h>
#include <string.h>

uint32_t ks_epoch_from_unix(uint64_t unix_seconds) {
    uint64_t e = unix_seconds / KS_EPOCH_SECONDS;
    return (e > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (uint32_t)e;
}

int ks_derive_epoch_key(const uint8_t k_room[KS_KEY_BYTES],
                        uint16_t key_version,
                        uint32_t epoch,
                        uint8_t out_key[KS_KEY_BYTES]) {
    if (!k_room || !out_key) return -1;

    /* info = "fear.epoch.v1" || key_version(2 LE) || epoch(4 LE) */
    static const char ctx[] = KS_EPOCH_CTX;
    uint8_t info[sizeof(ctx) - 1 + 2 + 4];
    size_t o = sizeof(ctx) - 1;
    memcpy(info, ctx, o);
    info[o++] = (uint8_t)(key_version & 0xFF);
    info[o++] = (uint8_t)((key_version >> 8) & 0xFF);
    info[o++] = (uint8_t)(epoch & 0xFF);
    info[o++] = (uint8_t)((epoch >> 8) & 0xFF);
    info[o++] = (uint8_t)((epoch >> 16) & 0xFF);
    info[o++] = (uint8_t)((epoch >> 24) & 0xFF);

    int rc = crypto_generichash(out_key, KS_KEY_BYTES,
                                info, sizeof(info),
                                k_room, KS_KEY_BYTES);
    sodium_memzero(info, sizeof(info));
    return (rc == 0) ? 0 : -1;
}

int ks_epoch_acceptable(uint32_t header_epoch, uint32_t local_epoch) {
    uint32_t diff = (header_epoch > local_epoch)
                        ? header_epoch - local_epoch
                        : local_epoch - header_epoch;
    return diff <= KS_EPOCH_SKEW;
}

void ks_write_header(uint8_t out[KS_HEADER_BYTES],
                     uint16_t key_version, uint32_t epoch) {
    if (!out) return;
    out[0] = (uint8_t)(key_version & 0xFF);
    out[1] = (uint8_t)((key_version >> 8) & 0xFF);
    out[2] = (uint8_t)(epoch & 0xFF);
    out[3] = (uint8_t)((epoch >> 8) & 0xFF);
    out[4] = (uint8_t)((epoch >> 16) & 0xFF);
    out[5] = (uint8_t)((epoch >> 24) & 0xFF);
}

void ks_read_header(const uint8_t in[KS_HEADER_BYTES],
                    uint16_t *key_version, uint32_t *epoch) {
    if (!in) return;
    if (key_version) {
        *key_version = (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
    }
    if (epoch) {
        *epoch = (uint32_t)in[2]
               | ((uint32_t)in[3] << 8)
               | ((uint32_t)in[4] << 16)
               | ((uint32_t)in[5] << 24);
    }
}
