/**
 * @file audio_codec.h
 * @brief Opus audio codec wrapper for F.E.A.R. audio calls
 *
 * Provides simplified interface to Opus encoder/decoder:
 * - Encoding PCM to compressed Opus frames
 * - Decoding Opus frames to PCM
 * - Bitrate and complexity configuration
 */

#ifndef AUDIO_CODEC_H
#define AUDIO_CODEC_H

#include "audio_types.h"
#include <stddef.h>
#include <stdint.h>

/* Forward declarations for Opus types */
typedef struct OpusEncoder OpusEncoder;
typedef struct OpusDecoder OpusDecoder;

/**
 * @struct AudioCodec
 * @brief Opus encoder/decoder state
 */
typedef struct {
    OpusEncoder *encoder;  /**< Opus encoder instance */
    OpusDecoder *decoder;  /**< Opus decoder instance */
} AudioCodec;

/**
 * @brief Initialize Opus encoder and decoder
 * @param codec Pointer to AudioCodec structure
 * @return 0 on success, -1 on failure
 * @note Uses 48kHz, mono, 20ms frames
 * @note Bitrate: 128 kbps (high quality), Complexity: 5 (balanced)
 */
int audio_codec_init(AudioCodec *codec);

/**
 * @brief Free Opus encoder and decoder
 * @param codec Pointer to AudioCodec structure
 */
void audio_codec_free(AudioCodec *codec);

/**
 * @brief Encode PCM frame to Opus format
 * @param codec Pointer to AudioCodec structure
 * @param pcm_in PCM input (SAMPLES_PER_FRAME samples, 16-bit)
 * @param opus_out Output buffer (must be at least MAX_OPUS_FRAME bytes)
 * @param max_bytes Maximum output size
 * @return Encoded bytes on success, negative on error
 */
int audio_codec_encode(AudioCodec *codec, const int16_t *pcm_in,
                       uint8_t *opus_out, int max_bytes);

/**
 * @brief Decode Opus frame to PCM format
 * @param codec Pointer to AudioCodec structure
 * @param opus_in Opus input data
 * @param opus_len Length of Opus data
 * @param pcm_out Output buffer (must hold SAMPLES_PER_FRAME samples)
 * @return Number of decoded samples, negative on error
 */
int audio_codec_decode(AudioCodec *codec, const uint8_t *opus_in,
                       int opus_len, int16_t *pcm_out);

#endif /* AUDIO_CODEC_H */
