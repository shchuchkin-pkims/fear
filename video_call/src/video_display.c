/**
 * @file video_display.c
 * @brief SDL3 YUV420P video display
 *
 * Renders decoded video frames using SDL3 hardware-accelerated
 * texture rendering with YUV420P (IYUV) format.
 */

#include "video_display.h"
#define SDL_MAIN_HANDLED
#include <SDL3/SDL.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct VideoDisplay {
    SDL_Window *window;
    SDL_Renderer *renderer;
    SDL_Texture *texture;
    int tex_width;
    int tex_height;
    /* Local camera PiP */
    SDL_Texture *local_texture;
    int local_tex_width;
    int local_tex_height;
    /* RTT overlay */
    uint32_t rtt_ms;
};

void video_display_set_rtt(VideoDisplay *disp, uint32_t rtt_ms) {
    if (disp) disp->rtt_ms = rtt_ms;
}

static void render_rtt_overlay(VideoDisplay *disp) {
    if (!disp || !disp->renderer) return;

    uint32_t rtt = disp->rtt_ms;
    char buf[32];
    snprintf(buf, sizeof(buf), "RTT: %u ms", rtt);

    /* Color: green < 100ms, yellow 100-300ms, red > 300ms */
    uint8_t r, g, b;
    if (rtt < 100) {
        r = 0; g = 220; b = 0;       /* green */
    } else if (rtt < 300) {
        r = 255; g = 200; b = 0;     /* yellow */
    } else {
        r = 255; g = 40; b = 40;     /* red */
    }

    /* Background for readability */
    float scale = 2.0f;
    float text_w = (float)strlen(buf) * 8.0f * scale;
    float text_h = 8.0f * scale;
    float pad = 4.0f;
    SDL_FRect bg = { 8 - pad, 8 - pad, text_w + pad * 2, text_h + pad * 2 };
    SDL_SetRenderDrawColor(disp->renderer, 0, 0, 0, 180);
    SDL_SetRenderDrawBlendMode(disp->renderer, SDL_BLENDMODE_BLEND);
    SDL_RenderFillRect(disp->renderer, &bg);

    /* Render text scaled 2x for readability */
    SDL_SetRenderScale(disp->renderer, scale, scale);
    SDL_SetRenderDrawColor(disp->renderer, r, g, b, 255);
    SDL_RenderDebugText(disp->renderer, 8.0f / scale, 8.0f / scale, buf);
    SDL_SetRenderScale(disp->renderer, 1.0f, 1.0f);
}

int video_display_open(VideoDisplay **disp, const char *title,
                       int width, int height) {
    if (!disp || width <= 0 || height <= 0) return -1;

    VideoDisplay *d = (VideoDisplay *)calloc(1, sizeof(VideoDisplay));
    if (!d) return -1;

    d->window = SDL_CreateWindow(
        title ? title : "F.E.A.R. Video",
        width, height,
        SDL_WINDOW_RESIZABLE);

    if (!d->window) {
        fprintf(stderr, "video_display: SDL_CreateWindow: %s\n", SDL_GetError());
        free(d);
        return -1;
    }

    d->renderer = SDL_CreateRenderer(d->window, NULL);
    if (!d->renderer) {
        fprintf(stderr, "video_display: SDL_CreateRenderer: %s\n", SDL_GetError());
        SDL_DestroyWindow(d->window);
        free(d);
        return -1;
    }

    SDL_SetRenderVSync(d->renderer, 1);

    d->texture = SDL_CreateTexture(d->renderer, SDL_PIXELFORMAT_IYUV,
                                    SDL_TEXTUREACCESS_STREAMING,
                                    width, height);
    if (!d->texture) {
        fprintf(stderr, "video_display: SDL_CreateTexture: %s\n", SDL_GetError());
        SDL_DestroyRenderer(d->renderer);
        SDL_DestroyWindow(d->window);
        free(d);
        return -1;
    }

    d->tex_width = width;
    d->tex_height = height;

    *disp = d;
    return 0;
}

int video_display_render(VideoDisplay *disp, const uint8_t *yuv,
                         int width, int height) {
    if (!disp || !yuv || width <= 0 || height <= 0) return -1;

    /* Recreate texture if dimensions changed */
    if (width != disp->tex_width || height != disp->tex_height) {
        if (disp->texture) SDL_DestroyTexture(disp->texture);
        disp->texture = SDL_CreateTexture(disp->renderer, SDL_PIXELFORMAT_IYUV,
                                           SDL_TEXTUREACCESS_STREAMING,
                                           width, height);
        if (!disp->texture) return -1;
        disp->tex_width = width;
        disp->tex_height = height;
    }

    int y_size = width * height;
    int uv_stride = width / 2;

    if (!SDL_UpdateYUVTexture(disp->texture, NULL,
                              yuv, width,                     /* Y plane */
                              yuv + y_size, uv_stride,         /* U plane */
                              yuv + y_size + y_size / 4, uv_stride)) { /* V plane */
        return -1;
    }

    SDL_RenderClear(disp->renderer);
    SDL_RenderTexture(disp->renderer, disp->texture, NULL, NULL);
    render_rtt_overlay(disp);
    SDL_RenderPresent(disp->renderer);

    return 0;
}

int video_display_render_pip(VideoDisplay *disp,
                             const uint8_t *remote_yuv, int remote_w, int remote_h,
                             const uint8_t *local_yuv, int local_w, int local_h) {
    /* Fall back to normal render if no local frame */
    if (!local_yuv || local_w <= 0 || local_h <= 0)
        return video_display_render(disp, remote_yuv, remote_w, remote_h);

    if (!disp || !remote_yuv || remote_w <= 0 || remote_h <= 0) return -1;

    /* Recreate remote texture if dimensions changed */
    if (remote_w != disp->tex_width || remote_h != disp->tex_height) {
        if (disp->texture) SDL_DestroyTexture(disp->texture);
        disp->texture = SDL_CreateTexture(disp->renderer, SDL_PIXELFORMAT_IYUV,
                                           SDL_TEXTUREACCESS_STREAMING,
                                           remote_w, remote_h);
        if (!disp->texture) return -1;
        disp->tex_width = remote_w;
        disp->tex_height = remote_h;
    }

    /* Update remote texture */
    int y_size = remote_w * remote_h;
    int uv_stride = remote_w / 2;
    if (!SDL_UpdateYUVTexture(disp->texture, NULL,
                              remote_yuv, remote_w,
                              remote_yuv + y_size, uv_stride,
                              remote_yuv + y_size + y_size / 4, uv_stride)) {
        return -1;
    }

    /* Recreate local PiP texture if dimensions changed */
    if (local_w != disp->local_tex_width || local_h != disp->local_tex_height) {
        if (disp->local_texture) SDL_DestroyTexture(disp->local_texture);
        disp->local_texture = SDL_CreateTexture(disp->renderer, SDL_PIXELFORMAT_IYUV,
                                                 SDL_TEXTUREACCESS_STREAMING,
                                                 local_w, local_h);
        if (!disp->local_texture) {
            /* Non-fatal: render remote only */
            disp->local_tex_width = 0;
            disp->local_tex_height = 0;
            SDL_RenderClear(disp->renderer);
            SDL_RenderTexture(disp->renderer, disp->texture, NULL, NULL);
            SDL_RenderPresent(disp->renderer);
            return 0;
        }
        disp->local_tex_width = local_w;
        disp->local_tex_height = local_h;
    }

    /* Update local texture */
    int ly_size = local_w * local_h;
    int luv_stride = local_w / 2;
    SDL_UpdateYUVTexture(disp->local_texture, NULL,
                          local_yuv, local_w,
                          local_yuv + ly_size, luv_stride,
                          local_yuv + ly_size + ly_size / 4, luv_stride);

    /* Render composited frame */
    SDL_RenderClear(disp->renderer);

    /* Remote: full window */
    SDL_RenderTexture(disp->renderer, disp->texture, NULL, NULL);

    /* PiP: 1/4 window width, aspect-ratio preserved, bottom-right with margin */
    int win_w, win_h;
    SDL_GetWindowSize(disp->window, &win_w, &win_h);

    int pip_w = win_w / 4;
    int pip_h = (pip_w * local_h) / local_w;
    int margin = 10;
    int border = 2;

    /* Dark border */
    SDL_FRect border_rect = {
        (float)(win_w - pip_w - margin - border),
        (float)(margin - border),
        (float)(pip_w + border * 2),
        (float)(pip_h + border * 2)
    };
    SDL_SetRenderDrawColor(disp->renderer, 32, 32, 32, 255);
    SDL_RenderFillRect(disp->renderer, &border_rect);

    /* PiP video */
    SDL_FRect pip_rect = {
        (float)(win_w - pip_w - margin),
        (float)margin,
        (float)pip_w,
        (float)pip_h
    };
    SDL_RenderTexture(disp->renderer, disp->local_texture, NULL, &pip_rect);

    render_rtt_overlay(disp);
    SDL_RenderPresent(disp->renderer);
    return 0;
}

void video_display_close(VideoDisplay *disp) {
    if (!disp) return;
    if (disp->local_texture) SDL_DestroyTexture(disp->local_texture);
    if (disp->texture) SDL_DestroyTexture(disp->texture);
    if (disp->renderer) SDL_DestroyRenderer(disp->renderer);
    if (disp->window) SDL_DestroyWindow(disp->window);
    free(disp);
}
