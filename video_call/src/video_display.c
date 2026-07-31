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
    /* One texture per grid cell. Senders differ in size - a landscape webcam
     * next to a portrait phone - so a single shared texture would be torn
     * down and rebuilt on every alternating frame. */
    struct {
        SDL_Texture *tex;
        int w;
        int h;
    } tile[VD_MAX_TILES];
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

/** Draw a participant's caption in the bottom-left of its cell. */
static void vd_cell_label(VideoDisplay *d, float x, float y, float ch,
                          const char *text) {
    if (!text || !text[0]) return;
    const float scale = 1.5f;
    float tw = (float)strlen(text) * 8.0f * scale;
    float th = 8.0f * scale;
    float pad = 3.0f;
    float tx = x + 6.0f;
    float ty = y + ch - th - 6.0f;

    SDL_SetRenderDrawBlendMode(d->renderer, SDL_BLENDMODE_BLEND);
    SDL_SetRenderDrawColor(d->renderer, 0, 0, 0, 170);
    SDL_FRect bg = { tx - pad, ty - pad, tw + pad * 2, th + pad * 2 };
    SDL_RenderFillRect(d->renderer, &bg);

    SDL_SetRenderScale(d->renderer, scale, scale);
    SDL_SetRenderDrawColor(d->renderer, 235, 235, 235, 255);
    SDL_RenderDebugText(d->renderer, tx / scale, ty / scale, text);
    SDL_SetRenderScale(d->renderer, 1.0f, 1.0f);
}

/**
 * Upload one participant's frame into its own texture, rebuilding it when
 * that sender's geometry changes.
 */
static SDL_Texture *vd_tile_texture(VideoDisplay *d, int i,
                                    const uint8_t *yuv, int w, int h) {
    if (i < 0 || i >= VD_MAX_TILES || !yuv || w <= 0 || h <= 0) return NULL;

    if (!d->tile[i].tex || d->tile[i].w != w || d->tile[i].h != h) {
        if (d->tile[i].tex) SDL_DestroyTexture(d->tile[i].tex);
        d->tile[i].tex = SDL_CreateTexture(d->renderer, SDL_PIXELFORMAT_IYUV,
                                           SDL_TEXTUREACCESS_STREAMING, w, h);
        if (!d->tile[i].tex) {
            d->tile[i].w = 0;
            d->tile[i].h = 0;
            return NULL;
        }
        d->tile[i].w = w;
        d->tile[i].h = h;
    }

    int y_size = w * h;
    int uv_stride = w / 2;
    if (!SDL_UpdateYUVTexture(d->tile[i].tex, NULL,
                              yuv, w,
                              yuv + y_size, uv_stride,
                              yuv + y_size + y_size / 4, uv_stride)) {
        return NULL;
    }
    return d->tile[i].tex;
}

/**
 * Column count that gives the largest picture.
 *
 * Trying every count instead of hardcoding a 2x2 is what makes a tall window
 * stack two participants rather than squeeze them side by side.
 */
static int vd_best_cols(int n, int win_w, int win_h, float aspect) {
    int best = 1;
    float best_area = -1.0f;
    for (int cols = 1; cols <= n; cols++) {
        int rows = (n + cols - 1) / cols;
        float cw = (float)win_w / (float)cols;
        float ch = (float)win_h / (float)rows;
        float w = cw, h = cw / aspect;
        if (h > ch) { h = ch; w = ch * aspect; }
        float area = w * h;
        if (area > best_area) {
            best_area = area;
            best = cols;
        }
    }
    return best;
}

/** Local camera preview, top-right, with a dark border. */
static void vd_render_local_pip(VideoDisplay *d,
                                const uint8_t *yuv, int w, int h) {
    if (!yuv || w <= 0 || h <= 0) return;

    if (w != d->local_tex_width || h != d->local_tex_height) {
        if (d->local_texture) SDL_DestroyTexture(d->local_texture);
        d->local_texture = SDL_CreateTexture(d->renderer, SDL_PIXELFORMAT_IYUV,
                                             SDL_TEXTUREACCESS_STREAMING, w, h);
        if (!d->local_texture) {
            d->local_tex_width = 0;
            d->local_tex_height = 0;
            return;
        }
        d->local_tex_width = w;
        d->local_tex_height = h;
    }

    int y_size = w * h;
    int uv_stride = w / 2;
    SDL_UpdateYUVTexture(d->local_texture, NULL,
                         yuv, w,
                         yuv + y_size, uv_stride,
                         yuv + y_size + y_size / 4, uv_stride);

    int win_w, win_h;
    SDL_GetWindowSize(d->window, &win_w, &win_h);

    int pip_w = win_w / 4;
    int pip_h = (pip_w * h) / w;
    int margin = 10;
    int border = 2;

    SDL_FRect border_rect = {
        (float)(win_w - pip_w - margin - border),
        (float)(margin - border),
        (float)(pip_w + border * 2),
        (float)(pip_h + border * 2)
    };
    SDL_SetRenderDrawColor(d->renderer, 32, 32, 32, 255);
    SDL_RenderFillRect(d->renderer, &border_rect);

    SDL_FRect pip_rect = {
        (float)(win_w - pip_w - margin),
        (float)margin,
        (float)pip_w,
        (float)pip_h
    };
    SDL_RenderTexture(d->renderer, d->local_texture, NULL, &pip_rect);
}

int video_display_render_grid(VideoDisplay *disp,
                              const VideoTile *tiles, int ntiles,
                              const uint8_t *local_yuv, int local_w, int local_h) {
    if (!disp || !disp->renderer || !tiles || ntiles <= 0) return -1;
    if (ntiles > VD_MAX_TILES) ntiles = VD_MAX_TILES;

    int win_w = 0, win_h = 0;
    SDL_GetWindowSize(disp->window, &win_w, &win_h);
    if (win_w <= 0 || win_h <= 0) return -1;

    /* Average the senders' aspects, so a portrait phone beside a landscape
     * webcam does not pick a layout that suits neither. */
    float aspect = 0.0f;
    int counted = 0;
    for (int i = 0; i < ntiles; i++) {
        if (!tiles[i].yuv || tiles[i].width <= 0 || tiles[i].height <= 0) continue;
        aspect += (float)tiles[i].width / (float)tiles[i].height;
        counted++;
    }
    aspect = counted ? (aspect / (float)counted) : (4.0f / 3.0f);

    int cols = vd_best_cols(ntiles, win_w, win_h, aspect);
    int rows = (ntiles + cols - 1) / cols;
    float cw = (float)win_w / (float)cols;
    float ch = (float)win_h / (float)rows;

    SDL_SetRenderDrawColor(disp->renderer, 16, 16, 16, 255);
    SDL_RenderClear(disp->renderer);

    for (int i = 0; i < ntiles; i++) {
        float cx = (float)(i % cols) * cw;
        float cy = (float)(i / cols) * ch;

        SDL_Texture *t = vd_tile_texture(disp, i, tiles[i].yuv,
                                         tiles[i].width, tiles[i].height);
        if (t) {
            float ta = (float)tiles[i].width / (float)tiles[i].height;
            float w = cw, h = cw / ta;
            if (h > ch) { h = ch; w = ch * ta; }
            SDL_FRect dst = { cx + (cw - w) / 2.0f, cy + (ch - h) / 2.0f, w, h };
            SDL_RenderTexture(disp->renderer, t, NULL, &dst);
        }
        vd_cell_label(disp, cx, cy, ch, tiles[i].label);
    }

    /* Separators, so two dark pictures do not read as one. */
    SDL_SetRenderDrawColor(disp->renderer, 64, 64, 64, 255);
    for (int c = 1; c < cols; c++) {
        SDL_FRect v = { (float)c * cw - 1.0f, 0.0f, 2.0f, (float)win_h };
        SDL_RenderFillRect(disp->renderer, &v);
    }
    for (int r = 1; r < rows; r++) {
        SDL_FRect hz = { 0.0f, (float)r * ch - 1.0f, (float)win_w, 2.0f };
        SDL_RenderFillRect(disp->renderer, &hz);
    }

    vd_render_local_pip(disp, local_yuv, local_w, local_h);
    render_rtt_overlay(disp);
    SDL_RenderPresent(disp->renderer);
    return 0;
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
    for (int i = 0; i < VD_MAX_TILES; i++) {
        if (disp->tile[i].tex) SDL_DestroyTexture(disp->tile[i].tex);
    }
    if (disp->local_texture) SDL_DestroyTexture(disp->local_texture);
    if (disp->texture) SDL_DestroyTexture(disp->texture);
    if (disp->renderer) SDL_DestroyRenderer(disp->renderer);
    if (disp->window) SDL_DestroyWindow(disp->window);
    free(disp);
}
