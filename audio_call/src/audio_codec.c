/**
 * @file audio_codec.c
 * @brief Opus audio codec wrapper implementation for F.E.A.R. audio calls
 *
 * Provides simplified interface for audio encoding/decoding using libopus.
 * Configured for voice calls with FEC (Forward Error Correction) enabled.
 */

#include "audio_codec.h"
#include <opus.h>
#include <stdio.h>
#include <string.h>

/* Opus configuration constants */
#define OPUS_APPLICATION   OPUS_APPLICATION_VOIP  /**< Optimized for voice */
#define OPUS_BITRATE       128000                  /**< 128 kbps bitrate (high quality) */
#define OPUS_COMPLEXITY    5                       /**< Complexity 0-10 (5=balanced) */

/**
 * @brief Initialize Opus encoder and decoder
 *
 * Creates encoder and decoder with configuration optimized for voice calls:
 * - Sample rate: 48000 Hz
 * - Channels: 1 (mono)
 * - Bitrate: 128 kbps (high quality)
 * - Complexity: 5 (balanced)
 * - FEC enabled (in-band forward error correction)
 * - 10% expected packet loss
 *
 * @param codec Pointer to AudioCodec structure
 * @return 0 on success, -1 on failure
 */
int audio_codec_init(AudioCodec *codec) {
    if (!codec) {
        return -1;
    }

    memset(codec, 0, sizeof(*codec));

    /* Create Opus encoder */
    int err = 0;
    codec->encoder = opus_encoder_create(SAMPLE_RATE, CHANNELS,
                                         OPUS_APPLICATION, &err);
    if (!codec->encoder || err != OPUS_OK) {
        fprintf(stderr, "opus_encoder_create error: %d\n", err);
        return -1;
    }

    /* Configure encoder for voice calls */
    opus_encoder_ctl(codec->encoder, OPUS_SET_BITRATE(OPUS_BITRATE));
    opus_encoder_ctl(codec->encoder, OPUS_SET_COMPLEXITY(OPUS_COMPLEXITY));
    opus_encoder_ctl(codec->encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    opus_encoder_ctl(codec->encoder, OPUS_SET_INBAND_FEC(1));  /* Enable FEC */
    opus_encoder_ctl(codec->encoder, OPUS_SET_PACKET_LOSS_PERC(10));

    /* Create Opus decoder */
    codec->decoder = opus_decoder_create(SAMPLE_RATE, CHANNELS, &err);
    if (!codec->decoder || err != OPUS_OK) {
        fprintf(stderr, "opus_decoder_create error: %d\n", err);
        if (codec->encoder) {
            opus_encoder_destroy(codec->encoder);
        }
        return -1;
    }

    return 0;
}

/**
 * @brief Free Opus encoder and decoder resources
 *
 * Safely destroys encoder and decoder instances.
 *
 * @param codec Pointer to AudioCodec structure
 * @note Safe to call even if init failed
 */
void audio_codec_free(AudioCodec *codec) {
    if (!codec) {
        return;
    }

    if (codec->encoder) {
        opus_encoder_destroy(codec->encoder);
        codec->encoder = NULL;
    }

    if (codec->decoder) {
        opus_decoder_destroy(codec->decoder);
        codec->decoder = NULL;
    }
}

/**
 * @brief Encode PCM frame to Opus format
 *
 * Compresses one frame of PCM audio to Opus bitstream.
 *
 * @param codec Pointer to AudioCodec structure
 * @param pcm_in PCM input (SAMPLES_PER_FRAME samples, 16-bit mono)
 * @param opus_out Output buffer (must be at least MAX_OPUS_FRAME bytes)
 * @param max_bytes Maximum output size
 * @return Number of encoded bytes on success (>0), negative on error
 */
int audio_codec_encode(AudioCodec *codec, const int16_t *pcm_in,
                       uint8_t *opus_out, int max_bytes) {
    if (!codec || !codec->encoder || !pcm_in || !opus_out || max_bytes <= 0) {
        return -1;
    }

    /* Encode PCM to Opus */
    int enc_bytes = opus_encode(codec->encoder, pcm_in, SAMPLES_PER_FRAME,
                                opus_out, max_bytes);

    if (enc_bytes < 0) {
        fprintf(stderr, "opus_encode error: %d\n", enc_bytes);
        return -1;
    }

    return enc_bytes;
}

/**
 * @brief Decode Opus frame to PCM format
 *
 * Decompresses Opus bitstream to PCM audio.
 *
 * @param codec Pointer to AudioCodec structure
 * @param opus_in Opus input data
 * @param opus_len Length of Opus data
 * @param pcm_out Output buffer (must hold SAMPLES_PER_FRAME samples)
 * @return Number of decoded samples on success (>0), negative on error
 *
 * @note If opus_in is NULL, generates silence (packet loss concealment)
 */
int audio_codec_decode(AudioCodec *codec, const uint8_t *opus_in,
                       int opus_len, int16_t *pcm_out) {
    if (!codec || !codec->decoder || !pcm_out) {
        return -1;
    }

    /* Decode Opus to PCM (FEC=0: no forward error correction on this call) */
    int dec_samples = opus_decode(codec->decoder, opus_in, opus_len,
                                  pcm_out, SAMPLES_PER_FRAME, 0);

    if (dec_samples < 0) {
        fprintf(stderr, "opus_decode error: %d\n", dec_samples);
        return -1;
    }

    /* Pad with silence if we got fewer samples than expected */
    if (dec_samples < SAMPLES_PER_FRAME) {
        memset(pcm_out + dec_samples * CHANNELS, 0,
               (SAMPLES_PER_FRAME - dec_samples) * CHANNELS * sizeof(int16_t));
    }

    return dec_samples;
}
