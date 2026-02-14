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
};

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
    SDL_RenderPresent(disp->renderer);

    return 0;
}

void video_display_close(VideoDisplay *disp) {
    if (!disp) return;
    if (disp->texture) SDL_DestroyTexture(disp->texture);
    if (disp->renderer) SDL_DestroyRenderer(disp->renderer);
    if (disp->window) SDL_DestroyWindow(disp->window);
    free(disp);
}
