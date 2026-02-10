/**
 * @file video_codec.h
 * @brief VP8 video codec API using FFmpeg libavcodec
 *
 * Provides VP8 encoding and decoding for F.E.A.R. video calls.
 * Configured for real-time communication with low latency.
 */

#ifndef VIDEO_CODEC_H
#define VIDEO_CODEC_H

#include "video_types.h"
#include <stdint.h>
#include <stddef.h>

/** Opaque encoder context */
typedef struct VideoEncoder VideoEncoder;

/** Opaque decoder context */
typedef struct VideoDecoder VideoDecoder;

/**
 * @brief Create and configure VP8 encoder
 * @param enc Pointer to receive allocated encoder
 * @param width Frame width
 * @param height Frame height
 * @param fps Target framerate
 * @param bitrate_kbps Target bitrate in kbps
 * @return 0 on success, -1 on error
 */
int video_encoder_open(VideoEncoder **enc, int width, int height,
                       int fps, int bitrate_kbps);

/**
 * @brief Encode one YUV420P frame to VP8
 * @param enc Encoder context
 * @param yuv_in YUV420P frame data (width*height*3/2 bytes)
 * @param vp8_out Output buffer for compressed VP8 data
 * @param max_out Maximum output size
 * @return Compressed data size on success, 0 if no output yet, -1 on error
 */
int video_encoder_encode(VideoEncoder *enc, const uint8_t *yuv_in,
                         uint8_t *vp8_out, int max_out);

/**
 * @brief Update encoder bitrate (for adaptive quality)
 * @param enc Encoder context
 * @param bitrate_kbps New target bitrate in kbps
 * @return 0 on success, -1 on error
 */
int video_encoder_set_bitrate(VideoEncoder *enc, int bitrate_kbps);

/**
 * @brief Close encoder and free resources
 * @param enc Encoder context (safe to pass NULL)
 */
void video_encoder_close(VideoEncoder *enc);

/**
 * @brief Create VP8 decoder
 * @param dec Pointer to receive allocated decoder
 * @return 0 on success, -1 on error
 */
int video_decoder_open(VideoDecoder **dec);

/**
 * @brief Decode VP8 frame to YUV420P
 * @param dec Decoder context
 * @param vp8_in Compressed VP8 data
 * @param vp8_len Length of compressed data
 * @param yuv_out Output buffer for YUV420P frame
 * @param max_out Maximum output size
 * @param out_width Receives decoded frame width
 * @param out_height Receives decoded frame height
 * @return Number of bytes written to yuv_out, 0 if no output, -1 on error
 */
int video_decoder_decode(VideoDecoder *dec, const uint8_t *vp8_in, int vp8_len,
                         uint8_t *yuv_out, int max_out,
                         int *out_width, int *out_height);

/**
 * @brief Close decoder and free resources
 * @param dec Decoder context (safe to pass NULL)
 */
void video_decoder_close(VideoDecoder *dec);

#endif /* VIDEO_CODEC_H */
