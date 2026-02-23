/**
 * @file video_capture.c
 * @brief Camera capture via FFmpeg libavdevice
 *
 * Uses V4L2 on Linux and dshow on Windows for camera access.
 * Automatically converts camera's native pixel format to YUV420P.
 */

#include "video_capture.h"
#include <libavdevice/avdevice.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libavutil/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct VideoCapture {
    AVFormatContext *fmt_ctx;
    AVCodecContext *dec_ctx;
    struct SwsContext *sws_ctx;
    AVFrame *raw_frame;
    AVFrame *yuv_frame;
    AVPacket *pkt;
    int stream_index;
    int cam_width;   /* camera native resolution */
    int cam_height;
    int width;       /* output resolution (may be downscaled) */
    int height;
};

/* ---- dshow device listing (Windows) ---- */
#ifdef _WIN32

/*
 * dshow's list_devices prints device names via av_log(), not stdout.
 * FFmpeg splits each logical line across MULTIPLE av_log() calls, e.g.:
 *   call 1: " \"GENERAL WEBCAM\""
 *   call 2: " (video)\n"
 *
 * So we must buffer partial output and process complete lines on '\n'.
 *
 * Complete lines look like:
 *   "GENERAL WEBCAM" (video)
 *   "OBS Virtual Camera" (none)
 *   "Microphone" (audio)
 *   Alternative name "@device_pnp_..."
 *
 * We capture only entries with (video) suffix.
 */

#define MAX_DSHOW_DEVICES 32
#define MAX_DEVICE_NAME   256

static struct {
    char names[MAX_DSHOW_DEVICES][MAX_DEVICE_NAME];
    int  count;
    char linebuf[2048];
    int  linepos;
} g_dshow_cameras;

static void dshow_process_line(const char *line) {
    /* Skip "Alternative name" lines */
    if (strstr(line, "Alternative name")) return;

    /* Must contain (video) to be a camera */
    if (!strstr(line, "(video)")) return;

    /* Extract quoted device name */
    const char *q1 = strchr(line, '"');
    if (!q1) return;
    const char *q2 = strchr(q1 + 1, '"');
    if (!q2) return;

    if (g_dshow_cameras.count < MAX_DSHOW_DEVICES) {
        size_t len = (size_t)(q2 - q1 - 1);
        if (len == 0) return;
        if (len >= MAX_DEVICE_NAME) len = MAX_DEVICE_NAME - 1;
        memcpy(g_dshow_cameras.names[g_dshow_cameras.count], q1 + 1, len);
        g_dshow_cameras.names[g_dshow_cameras.count][len] = '\0';
        g_dshow_cameras.count++;
    }
}

static void dshow_log_callback(void *ptr, int level, const char *fmt, va_list vl) {
    (void)ptr; (void)level;
    char tmp[2048];
    int len = vsnprintf(tmp, sizeof(tmp), fmt, vl);
    if (len <= 0) return;
    if (len >= (int)sizeof(tmp)) len = (int)sizeof(tmp) - 1;

    /* Accumulate into line buffer, process on newline */
    for (int i = 0; i < len; i++) {
        if (tmp[i] == '\n' ||
            g_dshow_cameras.linepos >= (int)sizeof(g_dshow_cameras.linebuf) - 1) {
            g_dshow_cameras.linebuf[g_dshow_cameras.linepos] = '\0';
            if (g_dshow_cameras.linepos > 0) {
                dshow_process_line(g_dshow_cameras.linebuf);
            }
            g_dshow_cameras.linepos = 0;
        } else {
            g_dshow_cameras.linebuf[g_dshow_cameras.linepos++] = tmp[i];
        }
    }
}

#endif /* _WIN32 */

int video_capture_list_devices(void) {
    avdevice_register_all();

#ifdef _WIN32
    AVInputFormat *ifmt = (AVInputFormat *)av_find_input_format("dshow");
    if (!ifmt) {
        fprintf(stderr, "dshow input format not available\n");
        return -1;
    }

    printf("Camera devices (DirectShow):\n");

    /* Install custom log callback to capture dshow output */
    g_dshow_cameras.count = 0;
    g_dshow_cameras.linepos = 0;
    av_log_set_callback(dshow_log_callback);

    AVDictionary *opts = NULL;
    av_dict_set(&opts, "list_devices", "true", 0);
    AVFormatContext *fc = NULL;
    avformat_open_input(&fc, "video=dummy", ifmt, &opts);
    av_dict_free(&opts);
    if (fc) avformat_close_input(&fc);

    /* Restore default log callback */
    av_log_set_callback(av_log_default_callback);

    /* Flush any remaining partial line in buffer */
    if (g_dshow_cameras.linepos > 0) {
        g_dshow_cameras.linebuf[g_dshow_cameras.linepos] = '\0';
        dshow_process_line(g_dshow_cameras.linebuf);
        g_dshow_cameras.linepos = 0;
    }

    /* Print captured camera names to stdout in structured format */
    if (g_dshow_cameras.count == 0) {
        printf("  (no cameras found)\n");
    } else {
        for (int i = 0; i < g_dshow_cameras.count; i++) {
            printf("  camera: %s\n", g_dshow_cameras.names[i]);
        }
    }
#else
    printf("Camera devices:\n");

    /* List V4L2 devices by checking common paths */
    for (int i = 0; i < 10; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/video%d", i);
        FILE *f = fopen(path, "r");
        if (f) {
            fclose(f);
            printf("  camera: %s\n", path);
        }
    }
#endif

    return 0;
}

int video_capture_open(VideoCapture **cap, const char *device,
                       int width, int height, int fps) {
    if (!cap) return -1;

    avdevice_register_all();

    VideoCapture *c = (VideoCapture *)calloc(1, sizeof(VideoCapture));
    if (!c) return -1;

    c->fmt_ctx = avformat_alloc_context();
    if (!c->fmt_ctx) {
        free(c);
        return -1;
    }

    AVDictionary *opts = NULL;
    char size_str[32], fps_str[16];
    snprintf(size_str, sizeof(size_str), "%dx%d", width, height);
    snprintf(fps_str, sizeof(fps_str), "%d", fps);

    const char *input_name;

#ifdef _WIN32
    char device_path[256];
    AVInputFormat *ifmt = (AVInputFormat *)av_find_input_format("dshow");
    if (!ifmt) {
        fprintf(stderr, "video_capture: dshow not available\n");
        avformat_free_context(c->fmt_ctx);
        free(c);
        return -1;
    }
    if (device && device[0] != '\0') {
        snprintf(device_path, sizeof(device_path), "video=%s", device);
    } else {
        /* Try to auto-detect first available camera */
        avdevice_register_all();
        g_dshow_cameras.count = 0;
        g_dshow_cameras.linepos = 0;
        av_log_set_callback(dshow_log_callback);
        AVDictionary *detect_opts = NULL;
        av_dict_set(&detect_opts, "list_devices", "true", 0);
        AVFormatContext *detect_fc = NULL;
        avformat_open_input(&detect_fc, "video=dummy", ifmt, &detect_opts);
        av_dict_free(&detect_opts);
        if (detect_fc) avformat_close_input(&detect_fc);
        av_log_set_callback(av_log_default_callback);
        if (g_dshow_cameras.linepos > 0) {
            g_dshow_cameras.linebuf[g_dshow_cameras.linepos] = '\0';
            dshow_process_line(g_dshow_cameras.linebuf);
        }

        if (g_dshow_cameras.count > 0) {
            snprintf(device_path, sizeof(device_path), "video=%s",
                     g_dshow_cameras.names[0]);
            fprintf(stderr, "video_capture: auto-selected camera: %s\n",
                    g_dshow_cameras.names[0]);
        } else {
            snprintf(device_path, sizeof(device_path), "video=0");
        }
    }
    input_name = device_path;
    av_dict_set(&opts, "video_size", size_str, 0);
    av_dict_set(&opts, "framerate", fps_str, 0);
    av_dict_set(&opts, "vcodec", "mjpeg", 0);        /* request compressed format from camera */
    av_dict_set(&opts, "rtbufsize", "50000000", 0);   /* 50 MB buffer (plenty for MJPEG) */
#else
    AVInputFormat *ifmt = (AVInputFormat *)av_find_input_format("v4l2");
    if (!ifmt) {
        fprintf(stderr, "video_capture: v4l2 not available\n");
        avformat_free_context(c->fmt_ctx);
        free(c);
        return -1;
    }
    if (device && device[0] != '\0') {
        input_name = device;
    } else {
        input_name = "/dev/video0";
    }
    av_dict_set(&opts, "video_size", size_str, 0);
    av_dict_set(&opts, "framerate", fps_str, 0);
    av_dict_set(&opts, "input_format", "mjpeg", 0);
#endif

    /* Suppress FFmpeg warnings/info globally (swscaler deprecation, libvpx version, etc.) */
    av_log_set_level(AV_LOG_ERROR);

    /* First attempt may fail if camera doesn't support requested params — suppress logs */
    av_log_set_level(AV_LOG_QUIET);
    int ret = avformat_open_input(&c->fmt_ctx, input_name, ifmt, &opts);
    av_log_set_level(AV_LOG_ERROR);
    av_dict_free(&opts);

    if (ret < 0) {
        /* Fallback: retry without specific video_size/framerate,
           let the camera choose its default parameters */
        fprintf(stderr, "video_capture: trying camera defaults "
                "(requested %dx%d@%dfps not available)...\n", width, height, fps);

        c->fmt_ctx = avformat_alloc_context();
        if (!c->fmt_ctx) { free(c); return -1; }

        AVDictionary *opts2 = NULL;
#ifdef _WIN32
        av_dict_set(&opts2, "vcodec", "mjpeg", 0);
        av_dict_set(&opts2, "rtbufsize", "50000000", 0);
#else
        av_dict_set(&opts2, "input_format", "mjpeg", 0);
#endif
        ret = avformat_open_input(&c->fmt_ctx, input_name, ifmt, &opts2);
        av_dict_free(&opts2);

        if (ret < 0) {
            char errbuf[256];
            av_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "video_capture: cannot open '%s': %s\n", input_name, errbuf);
            free(c);
            return -1;
        }
    }

    if (avformat_find_stream_info(c->fmt_ctx, NULL) < 0) {
        fprintf(stderr, "video_capture: cannot find stream info\n");
        avformat_close_input(&c->fmt_ctx);
        free(c);
        return -1;
    }

    /* Find video stream */
    c->stream_index = -1;
    for (unsigned i = 0; i < c->fmt_ctx->nb_streams; i++) {
        if (c->fmt_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
            c->stream_index = (int)i;
            break;
        }
    }
    if (c->stream_index < 0) {
        fprintf(stderr, "video_capture: no video stream found\n");
        avformat_close_input(&c->fmt_ctx);
        free(c);
        return -1;
    }

    AVCodecParameters *par = c->fmt_ctx->streams[c->stream_index]->codecpar;
    const AVCodec *dec = avcodec_find_decoder(par->codec_id);
    if (!dec) {
        fprintf(stderr, "video_capture: decoder not found for codec %d\n", par->codec_id);
        avformat_close_input(&c->fmt_ctx);
        free(c);
        return -1;
    }

    c->dec_ctx = avcodec_alloc_context3(dec);
    avcodec_parameters_to_context(c->dec_ctx, par);
    c->dec_ctx->thread_count = 1;

    if (avcodec_open2(c->dec_ctx, dec, NULL) < 0) {
        fprintf(stderr, "video_capture: cannot open decoder\n");
        avcodec_free_context(&c->dec_ctx);
        avformat_close_input(&c->fmt_ctx);
        free(c);
        return -1;
    }

    c->cam_width = c->dec_ctx->width;
    c->cam_height = c->dec_ctx->height;

    /* Output at the requested dimensions, downscaling if camera resolution is larger */
    if (width > 0 && height > 0 && (c->cam_width > width || c->cam_height > height)) {
        c->width = width;
        c->height = height;
        fprintf(stderr, "video_capture: downscaling %dx%d -> %dx%d\n",
                c->cam_width, c->cam_height, c->width, c->height);
    } else {
        c->width = c->cam_width;
        c->height = c->cam_height;
    }

    /* Setup pixel format converter (+ downscaler if needed) to YUV420P */
    c->sws_ctx = sws_getContext(c->cam_width, c->cam_height, c->dec_ctx->pix_fmt,
                                 c->width, c->height, AV_PIX_FMT_YUV420P,
                                 SWS_FAST_BILINEAR, NULL, NULL, NULL);
    if (!c->sws_ctx) {
        fprintf(stderr, "video_capture: sws_getContext failed\n");
        avcodec_free_context(&c->dec_ctx);
        avformat_close_input(&c->fmt_ctx);
        free(c);
        return -1;
    }

    c->raw_frame = av_frame_alloc();
    c->yuv_frame = av_frame_alloc();
    c->pkt = av_packet_alloc();

    if (!c->raw_frame || !c->yuv_frame || !c->pkt) {
        video_capture_close(c);
        return -1;
    }

    c->yuv_frame->format = AV_PIX_FMT_YUV420P;
    c->yuv_frame->width = c->width;
    c->yuv_frame->height = c->height;
    if (av_frame_get_buffer(c->yuv_frame, 32) < 0) {
        video_capture_close(c);
        return -1;
    }

    printf("Camera opened: %s (%dx%d -> %dx%d)\n", input_name,
           c->cam_width, c->cam_height, c->width, c->height);
    *cap = c;
    return 0;
}

int video_capture_read(VideoCapture *cap, uint8_t *yuv_out, int max_size) {
    if (!cap || !yuv_out) return -1;

    int y_size = cap->width * cap->height;
    int total_size = y_size + 2 * (y_size / 4);
    if (total_size > max_size) return -1;

    while (1) {
        int ret = av_read_frame(cap->fmt_ctx, cap->pkt);
        if (ret < 0) return -1;

        if (cap->pkt->stream_index != cap->stream_index) {
            av_packet_unref(cap->pkt);
            continue;
        }

        ret = avcodec_send_packet(cap->dec_ctx, cap->pkt);
        av_packet_unref(cap->pkt);
        if (ret < 0) continue;

        ret = avcodec_receive_frame(cap->dec_ctx, cap->raw_frame);
        if (ret == AVERROR(EAGAIN)) continue;
        if (ret < 0) return -1;

        /* Convert to YUV420P (and downscale if camera res > output res) */
        sws_scale(cap->sws_ctx,
                  (const uint8_t * const *)cap->raw_frame->data,
                  cap->raw_frame->linesize,
                  0, cap->cam_height,
                  cap->yuv_frame->data, cap->yuv_frame->linesize);

        /* Copy YUV420P to contiguous output buffer */
        int offset = 0;
        /* Y plane */
        for (int row = 0; row < cap->height; row++) {
            memcpy(yuv_out + offset,
                   cap->yuv_frame->data[0] + row * cap->yuv_frame->linesize[0],
                   cap->width);
            offset += cap->width;
        }
        /* U plane */
        for (int row = 0; row < cap->height / 2; row++) {
            memcpy(yuv_out + offset,
                   cap->yuv_frame->data[1] + row * cap->yuv_frame->linesize[1],
                   cap->width / 2);
            offset += cap->width / 2;
        }
        /* V plane */
        for (int row = 0; row < cap->height / 2; row++) {
            memcpy(yuv_out + offset,
                   cap->yuv_frame->data[2] + row * cap->yuv_frame->linesize[2],
                   cap->width / 2);
            offset += cap->width / 2;
        }

        return offset;
    }
}

int video_capture_read_latest(VideoCapture *cap, uint8_t *yuv_out, int max_size) {
    if (!cap || !yuv_out) return -1;

    /* Read first frame (blocking) */
    int ret = video_capture_read(cap, yuv_out, max_size);
    if (ret <= 0) return ret;

    /* Drain any additional buffered frames non-blockingly.
       On Windows dshow, this prevents rtbufsize from filling up. */
    int drained = 0;
    while (1) {
        /* Try to read another frame without blocking.
           av_read_frame will return AVERROR(EAGAIN) or similar if no more
           buffered frames are available on some backends. On dshow it may
           still block briefly, so we limit drain count. */
        if (drained >= 10) break; /* safety limit */

        int got = av_read_frame(cap->fmt_ctx, cap->pkt);
        if (got < 0) break;

        if (cap->pkt->stream_index != cap->stream_index) {
            av_packet_unref(cap->pkt);
            continue;
        }

        got = avcodec_send_packet(cap->dec_ctx, cap->pkt);
        av_packet_unref(cap->pkt);
        if (got < 0) break;

        got = avcodec_receive_frame(cap->dec_ctx, cap->raw_frame);
        if (got < 0) break;

        /* Convert to YUV420P */
        sws_scale(cap->sws_ctx,
                  (const uint8_t * const *)cap->raw_frame->data,
                  cap->raw_frame->linesize,
                  0, cap->cam_height,
                  cap->yuv_frame->data, cap->yuv_frame->linesize);

        /* Copy to output (overwrite previous frame) */
        int offset = 0;
        for (int row = 0; row < cap->height; row++) {
            memcpy(yuv_out + offset,
                   cap->yuv_frame->data[0] + row * cap->yuv_frame->linesize[0],
                   cap->width);
            offset += cap->width;
        }
        for (int row = 0; row < cap->height / 2; row++) {
            memcpy(yuv_out + offset,
                   cap->yuv_frame->data[1] + row * cap->yuv_frame->linesize[1],
                   cap->width / 2);
            offset += cap->width / 2;
        }
        for (int row = 0; row < cap->height / 2; row++) {
            memcpy(yuv_out + offset,
                   cap->yuv_frame->data[2] + row * cap->yuv_frame->linesize[2],
                   cap->width / 2);
            offset += cap->width / 2;
        }

        ret = offset;
        drained++;
    }

    return ret;
}

void video_capture_get_size(VideoCapture *cap, int *width, int *height) {
    if (!cap) return;
    if (width) *width = cap->width;
    if (height) *height = cap->height;
}

void video_capture_close(VideoCapture *cap) {
    if (!cap) return;
    if (cap->pkt) av_packet_free(&cap->pkt);
    if (cap->raw_frame) av_frame_free(&cap->raw_frame);
    if (cap->yuv_frame) av_frame_free(&cap->yuv_frame);
    if (cap->sws_ctx) sws_freeContext(cap->sws_ctx);
    if (cap->dec_ctx) avcodec_free_context(&cap->dec_ctx);
    if (cap->fmt_ctx) avformat_close_input(&cap->fmt_ctx);
    free(cap);
}
