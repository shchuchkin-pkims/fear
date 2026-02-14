/**
 * @file audio_crypto.c
 * @brief AES-GCM encryption for F.E.A.R. audio calls
 *
 * Implements authenticated encryption using libsodium's AES-256-GCM.
 * Uses 12-byte nonces with 4-byte prefix + 8-byte sequence number.
 */

#include "audio_crypto.h"
#include "audio_network.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

/* AES-GCM constants from libsodium */
#define AES_GCM_NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES  /* 12 bytes */
#define AES_GCM_ABYTES    crypto_aead_aes256gcm_ABYTES     /* 16 bytes tag */
#define NONCE_PREFIX_LEN  4                                /* 4-byte prefix */

/* Packet version markers */
#define PKT_VER_AUDIO     0x01

/**
 * @brief Build AES-GCM nonce from prefix and sequence number
 *
 * Nonce structure (12 bytes total):
 * - bytes 0-3: 4-byte prefix (prevents nonce reuse between parties)
 * - bytes 4-11: 8-byte sequence number (network byte order)
 *
 * @param out Output buffer (must be AES_GCM_NONCE_LEN bytes)
 * @param prefix 4-byte prefix (unique per sender)
 * @param seq Sequence number (monotonically increasing)
 */
static void make_nonce(uint8_t out[AES_GCM_NONCE_LEN],
                       const uint8_t prefix[NONCE_PREFIX_LEN],
                       uint64_t seq) {
    /* Copy prefix to first 4 bytes */
    memcpy(out, prefix, NONCE_PREFIX_LEN);

    /* Convert sequence to network byte order and copy to bytes 4-11 */
    uint64_t be_seq = htonll_u64(seq);
    memcpy(out + NONCE_PREFIX_LEN, &be_seq, sizeof(be_seq));
}

/**
 * @brief Encrypt audio packet with AES-256-GCM
 *
 * Packet format:
 * - byte 0: Version (PKT_VER_AUDIO = 0x01)
 * - bytes 1-8: Sequence number (network byte order)
 * - bytes 9+: Encrypted opus data + 16-byte auth tag
 *
 * @param opus Opus-encoded audio data
 * @param opus_len Length of opus data
 * @param key 32-byte AES key
 * @param local_prefix 4-byte nonce prefix (sender-specific)
 * @param seq Sequence number for replay protection
 * @param out Output buffer (must be at least 1 + 8 + opus_len + 16 bytes)
 * @param out_len Receives actual output length
 * @return 0 on success, -1 on encryption failure
 */
int audio_encrypt_packet(const uint8_t *opus, size_t opus_len,
                         const uint8_t key[AUDIO_KEY_SIZE],
                         const uint8_t local_prefix[4],
                         uint64_t seq,
                         uint8_t *out, size_t *out_len) {
    if (!opus || !key || !local_prefix || !out || !out_len) {
        return -1;
    }

    /* Build nonce from prefix + sequence */
    uint8_t nonce[AES_GCM_NONCE_LEN];
    make_nonce(nonce, local_prefix, seq);

    /* Write packet header */
    out[0] = PKT_VER_AUDIO;
    uint64_t be_seq = htonll_u64(seq);
    memcpy(out + 1, &be_seq, sizeof(be_seq));

    /* Encrypt opus data with AES-256-GCM */
    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            out + 1 + sizeof(be_seq), &clen,
            opus, opus_len,
            NULL, 0,        /* No additional authenticated data */
            NULL,           /* No secret nonce (using public nonce) */
            nonce, key) != 0) {
        return -1;
    }

    *out_len = 1 + sizeof(be_seq) + (size_t)clen;
    return 0;
}

/**
 * @brief Decrypt audio packet with AES-256-GCM
 *
 * Verifies packet format, extracts sequence number, and decrypts opus data.
 *
 * @param pkt Encrypted packet (format: [ver][seq][encrypted+tag])
 * @param pkt_len Length of packet
 * @param key 32-byte AES key
 * @param remote_prefix 4-byte nonce prefix (sender-specific)
 * @param opus_out Output buffer for decrypted opus data
 * @param opus_len Receives length of decrypted opus data
 * @return 0 on success, -1 on error, -2 if remote prefix not ready
 *
 * @note Returns -1 if authentication fails (message tampered)
 */
int audio_decrypt_packet(const uint8_t *pkt, size_t pkt_len,
                         const uint8_t key[AUDIO_KEY_SIZE],
                         const uint8_t remote_prefix[4],
                         uint8_t *opus_out, size_t *opus_len) {
    if (!pkt || !key || !remote_prefix || !opus_out || !opus_len) {
        return -1;
    }

    /* Validate minimum packet size: 1 (ver) + 8 (seq) + 16 (tag) */
    if (pkt_len < 1 + 8 + AES_GCM_ABYTES) {
        return -1;
    }

    /* Verify packet version */
    if (pkt[0] != PKT_VER_AUDIO) {
        return -1;
    }

    /* Extract sequence number */
    uint64_t be_seq;
    memcpy(&be_seq, pkt + 1, 8);
    uint64_t seq = ntohll_u64(be_seq);

    /* Build nonce from remote prefix + sequence */
    uint8_t nonce[AES_GCM_NONCE_LEN];
    make_nonce(nonce, remote_prefix, seq);

    /* Decrypt and verify authentication tag */
    unsigned long long mlen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            opus_out, &mlen,
            NULL,           /* No secret nonce */
            pkt + 1 + 8, pkt_len - (1 + 8),
            NULL, 0,        /* No additional authenticated data */
            nonce, key) != 0) {
        return -1;  /* Authentication failed or decryption error */
    }

    *opus_len = (size_t)mlen;
    return 0;
}

/**
 * @brief Generic encrypt function (simplified API)
 *
 * This is a simpler version that generates random nonce internally.
 * Less efficient than packet-based encryption but easier to use.
 *
 * @param plaintext Input data to encrypt
 * @param plaintext_len Length of plaintext
 * @param key 32-byte encryption key
 * @param ciphertext Output buffer (must be plaintext_len + 28 bytes)
 * @param ciphertext_len Receives actual ciphertext length
 * @return 0 on success, -1 on error
 */
int audio_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                  const uint8_t key[AUDIO_KEY_SIZE],
                  uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!plaintext || !key || !ciphertext || !ciphertext_len) {
        return -1;
    }

    /* Generate random nonce */
    uint8_t nonce[AES_GCM_NONCE_LEN];
    randombytes_buf(nonce, sizeof(nonce));

    /* Copy nonce to output (first 12 bytes) */
    memcpy(ciphertext, nonce, AES_GCM_NONCE_LEN);

    /* Encrypt data after nonce */
    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            ciphertext + AES_GCM_NONCE_LEN, &clen,
            plaintext, plaintext_len,
            NULL, 0, NULL, nonce, key) != 0) {
        return -1;
    }

    *ciphertext_len = AES_GCM_NONCE_LEN + (size_t)clen;
    return 0;
}

/**
 * @brief Generic decrypt function (simplified API)
 *
 * Decrypts data encrypted with audio_encrypt().
 *
 * @param ciphertext Input data (with nonce and tag)
 * @param ciphertext_len Length of ciphertext
 * @param key 32-byte decryption key
 * @param plaintext Output buffer (at least ciphertext_len - 28 bytes)
 * @param plaintext_len Receives actual plaintext length
 * @return 0 on success, -1 on authentication failure
 */
int audio_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t key[AUDIO_KEY_SIZE],
                  uint8_t *plaintext, size_t *plaintext_len) {
    if (!ciphertext || !key || !plaintext || !plaintext_len) {
        return -1;
    }

    /* Validate minimum size */
    if (ciphertext_len < AES_GCM_NONCE_LEN + AES_GCM_ABYTES) {
        return -1;
    }

    /* Extract nonce from first 12 bytes */
    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, ciphertext, AES_GCM_NONCE_LEN);

    /* Decrypt data after nonce */
    unsigned long long mlen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            plaintext, &mlen, NULL,
            ciphertext + AES_GCM_NONCE_LEN,
            ciphertext_len - AES_GCM_NONCE_LEN,
            NULL, 0, nonce, key) != 0) {
        return -1;
    }

    *plaintext_len = (size_t)mlen;
    return 0;
}

/**
 * @brief Convert hexadecimal string to binary data
 *
 * Converts hex string (e.g., "a1b2c3...") to raw bytes.
 *
 * @param hex Input hex string (must be exactly out_len*2 characters)
 * @param out Output buffer
 * @param out_len Expected output length in bytes
 * @return 0 on success, -1 if hex length mismatch or invalid characters
 *
 * @example hex2bytes("a1b2", buf, 2) -> buf = {0xa1, 0xb2}
 */
int hex2bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || !out) {
        return -1;
    }

    size_t hlen = strlen(hex);
    if (hlen != out_len * 2) {
        return -1;  /* Hex string must be exactly 2*out_len characters */
    }

    /* Convert each pair of hex digits to one byte */
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) {
            return -1;  /* Invalid hex character */
        }
        out[i] = (uint8_t)v;
    }

    return 0;
}
