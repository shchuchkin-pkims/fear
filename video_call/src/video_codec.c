/**
 * @file video_codec.c
 * @brief VP8 video codec using FFmpeg libavcodec
 *
 * Provides VP8 encoding and decoding configured for real-time
 * communication with low latency.
 */

#include "video_codec.h"
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libavutil/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ===== Encoder ===== */

struct VideoEncoder {
    const AVCodec *codec;
    AVCodecContext *ctx;
    AVFrame *frame;
    AVPacket *pkt;
    int width;
    int height;
    int64_t pts;
};

int video_encoder_open(VideoEncoder **enc, int width, int height,
                       int fps, int bitrate_kbps) {
    if (!enc || width <= 0 || height <= 0 || fps <= 0) return -1;

    VideoEncoder *e = (VideoEncoder *)calloc(1, sizeof(VideoEncoder));
    if (!e) return -1;

    e->codec = avcodec_find_encoder(AV_CODEC_ID_VP8);
    if (!e->codec) {
        fprintf(stderr, "video_codec: VP8 encoder not found\n");
        free(e);
        return -1;
    }

    e->ctx = avcodec_alloc_context3(e->codec);
    if (!e->ctx) {
        free(e);
        return -1;
    }

    e->ctx->bit_rate = (int64_t)bitrate_kbps * 1000;
    e->ctx->width = width;
    e->ctx->height = height;
    e->ctx->time_base = (AVRational){1, fps};
    e->ctx->framerate = (AVRational){fps, 1};
    e->ctx->gop_size = fps * 2; /* Keyframe every 2 seconds */
    e->ctx->max_b_frames = 0;   /* No B-frames for real-time */
    e->ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    e->ctx->thread_count = 1;
    e->ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;

    /* Real-time tuning */
    av_opt_set(e->ctx->priv_data, "deadline", "realtime", 0);
    av_opt_set(e->ctx->priv_data, "cpu-used", "8", 0);
    av_opt_set(e->ctx->priv_data, "error-resilient", "1", 0);

    /* Suppress libvpx version banner and other info/warning messages */
    av_log_set_level(AV_LOG_ERROR);

    if (avcodec_open2(e->ctx, e->codec, NULL) < 0) {
        fprintf(stderr, "video_codec: failed to open VP8 encoder\n");
        avcodec_free_context(&e->ctx);
        free(e);
        return -1;
    }

    e->frame = av_frame_alloc();
    if (!e->frame) {
        avcodec_free_context(&e->ctx);
        free(e);
        return -1;
    }
    e->frame->format = AV_PIX_FMT_YUV420P;
    e->frame->width = width;
    e->frame->height = height;

    if (av_frame_get_buffer(e->frame, 32) < 0) {
        av_frame_free(&e->frame);
        avcodec_free_context(&e->ctx);
        free(e);
        return -1;
    }

    e->pkt = av_packet_alloc();
    if (!e->pkt) {
        av_frame_free(&e->frame);
        avcodec_free_context(&e->ctx);
        free(e);
        return -1;
    }

    e->width = width;
    e->height = height;
    e->pts = 0;

    *enc = e;
    return 0;
}

int video_encoder_encode(VideoEncoder *enc, const uint8_t *yuv_in,
                         uint8_t *vp8_out, int max_out) {
    if (!enc || !yuv_in || !vp8_out) return -1;

    if (av_frame_make_writable(enc->frame) < 0) return -1;

    /* Copy YUV420P data into AVFrame planes */
    int y_size = enc->width * enc->height;
    int uv_size = y_size / 4;

    memcpy(enc->frame->data[0], yuv_in, y_size);
    memcpy(enc->frame->data[1], yuv_in + y_size, uv_size);
    memcpy(enc->frame->data[2], yuv_in + y_size + uv_size, uv_size);

    enc->frame->pts = enc->pts++;

    int ret = avcodec_send_frame(enc->ctx, enc->frame);
    if (ret < 0) return -1;

    ret = avcodec_receive_packet(enc->ctx, enc->pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) return 0;
    if (ret < 0) return -1;

    if (enc->pkt->size > max_out) {
        av_packet_unref(enc->pkt);
        return -1;
    }

    memcpy(vp8_out, enc->pkt->data, enc->pkt->size);
    int size = enc->pkt->size;
    av_packet_unref(enc->pkt);

    return size;
}

int video_encoder_set_bitrate(VideoEncoder *enc, int bitrate_kbps) {
    if (!enc) return -1;
    enc->ctx->bit_rate = (int64_t)bitrate_kbps * 1000;
    return 0;
}

void video_encoder_close(VideoEncoder *enc) {
    if (!enc) return;
    if (enc->pkt) av_packet_free(&enc->pkt);
    if (enc->frame) av_frame_free(&enc->frame);
    if (enc->ctx) avcodec_free_context(&enc->ctx);
    free(enc);
}

/* ===== Decoder ===== */

struct VideoDecoder {
    const AVCodec *codec;
    AVCodecContext *ctx;
    AVFrame *frame;
    AVPacket *pkt;
};

int video_decoder_open(VideoDecoder **dec) {
    if (!dec) return -1;

    VideoDecoder *d = (VideoDecoder *)calloc(1, sizeof(VideoDecoder));
    if (!d) return -1;

    d->codec = avcodec_find_decoder(AV_CODEC_ID_VP8);
    if (!d->codec) {
        fprintf(stderr, "video_codec: VP8 decoder not found\n");
        free(d);
        return -1;
    }

    d->ctx = avcodec_alloc_context3(d->codec);
    if (!d->ctx) {
        free(d);
        return -1;
    }

    d->ctx->thread_count = 1;
    d->ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;

    if (avcodec_open2(d->ctx, d->codec, NULL) < 0) {
        fprintf(stderr, "video_codec: failed to open VP8 decoder\n");
        avcodec_free_context(&d->ctx);
        free(d);
        return -1;
    }

    d->frame = av_frame_alloc();
    if (!d->frame) {
        avcodec_free_context(&d->ctx);
        free(d);
        return -1;
    }

    d->pkt = av_packet_alloc();
    if (!d->pkt) {
        av_frame_free(&d->frame);
        avcodec_free_context(&d->ctx);
        free(d);
        return -1;
    }

    *dec = d;
    return 0;
}

int video_decoder_decode(VideoDecoder *dec, const uint8_t *vp8_in, int vp8_len,
                         uint8_t *yuv_out, int max_out,
                         int *out_width, int *out_height) {
    if (!dec || !vp8_in || vp8_len <= 0 || !yuv_out) return -1;

    dec->pkt->data = (uint8_t *)vp8_in;
    dec->pkt->size = vp8_len;

    int ret = avcodec_send_packet(dec->ctx, dec->pkt);
    if (ret < 0) return -1;

    ret = avcodec_receive_frame(dec->ctx, dec->frame);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) return 0;
    if (ret < 0) return -1;

    int w = dec->frame->width;
    int h = dec->frame->height;
    int y_size = w * h;
    int uv_size = y_size / 4;
    int total = y_size + 2 * uv_size;

    if (total > max_out) return -1;

    /* Copy YUV420P planes to contiguous output */
    /* Y plane */
    for (int row = 0; row < h; row++) {
        memcpy(yuv_out + row * w, dec->frame->data[0] + row * dec->frame->linesize[0], w);
    }
    /* U plane */
    for (int row = 0; row < h / 2; row++) {
        memcpy(yuv_out + y_size + row * (w / 2),
               dec->frame->data[1] + row * dec->frame->linesize[1], w / 2);
    }
    /* V plane */
    for (int row = 0; row < h / 2; row++) {
        memcpy(yuv_out + y_size + uv_size + row * (w / 2),
               dec->frame->data[2] + row * dec->frame->linesize[2], w / 2);
    }

    if (out_width) *out_width = w;
    if (out_height) *out_height = h;

    return total;
}

void video_decoder_close(VideoDecoder *dec) {
    if (!dec) return;
    if (dec->pkt) av_packet_free(&dec->pkt);
    if (dec->frame) av_frame_free(&dec->frame);
    if (dec->ctx) avcodec_free_context(&dec->ctx);
    free(dec);
}
