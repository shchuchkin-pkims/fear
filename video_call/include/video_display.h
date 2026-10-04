/**
 * @file video_display.h
 * @brief SDL3 video display API
 *
 * Renders YUV420P video frames using SDL3 hardware-accelerated
 * texture rendering. Runs in its own window.
 */

#ifndef VIDEO_DISPLAY_H
#define VIDEO_DISPLAY_H

#include <stdint.h>

/** Opaque display context */
typedef struct VideoDisplay VideoDisplay;

/** Participants the grid shows at once. */
#define VD_MAX_TILES 4

/**
 * @struct VideoTile
 * @brief One participant's picture in the grid
 */
typedef struct {
    const uint8_t *yuv;   /**< YUV420P frame, or NULL for an empty cell */
    int width;            /**< frame width */
    int height;           /**< frame height */
    const char *label;    /**< short caption drawn in the cell, or NULL */
    int speaking;         /**< outlined as the one talking */
    int pinned;           /**< outlined as chosen by the user */
    int on_main;          /**< outlined as the one on the big view */
} VideoTile;

/**
 * @brief Create SDL3 display window
 * @param disp Pointer to receive allocated display context
 * @param title Window title
 * @param width Initial window width
 * @param height Initial window height
 * @return 0 on success, -1 on error
 *
 * @note SDL3 must be initialized before calling this function.
 */
int video_display_open(VideoDisplay **disp, const char *title,
                       int width, int height);

/**
 * @brief Render one YUV420P frame
 * @param disp Display context
 * @param yuv YUV420P frame data
 * @param width Frame width (may differ from window size)
 * @param height Frame height
 * @return 0 on success, -1 on error
 *
 * Automatically resizes texture if frame dimensions change.
 */
int video_display_render(VideoDisplay *disp, const uint8_t *yuv,
                         int width, int height);

/**
 * @brief Render remote frame with local camera PiP overlay
 * @param disp Display context
 * @param remote_yuv Remote YUV420P frame
 * @param remote_w Remote frame width
 * @param remote_h Remote frame height
 * @param local_yuv Local camera YUV420P frame (NULL to skip PiP)
 * @param local_w Local frame width
 * @param local_h Local frame height
 * @return 0 on success, -1 on error
 *
 * Renders the remote video full-window with a small local camera
 * preview in the bottom-right corner. Falls back to normal render
 * if local_yuv is NULL.
 */
int video_display_render_pip(VideoDisplay *disp,
                             const uint8_t *remote_yuv, int remote_w, int remote_h,
                             const uint8_t *local_yuv, int local_w, int local_h);

/**
 * @brief Render several participants at once, tiled, with local PiP
 * @param disp Display context
 * @param tiles Participants to show, in a stable order
 * @param ntiles How many, clamped to VD_MAX_TILES
 * @param local_yuv Local camera frame (NULL to skip PiP)
 * @param local_w Local frame width
 * @param local_h Local frame height
 * @return 0 on success, -1 on error
 *
 * Each participant keeps its own texture, since senders differ in size and
 * a shared one would be destroyed and rebuilt on every alternating frame.
 * The column count is chosen for the largest picture rather than fixed, so
 * a portrait window stacks two participants instead of squeezing them side
 * by side. Pictures are letterboxed inside their cell: a black margin is
 * better than a stretched face.
 */
int video_display_render_grid(VideoDisplay *disp,
                              const VideoTile *tiles, int ntiles,
                              const uint8_t *local_yuv, int local_w, int local_h);

/**
 * @brief Render one participant large with the rest in a strip
 * @param disp Display context
 * @param main_tile The participant on the big view, or NULL for none
 * @param tiles Everyone, in a stable order, for the strip
 * @param ntiles How many, clamped to VD_MAX_TILES
 * @param local_yuv Local camera frame (NULL to skip PiP)
 * @param local_w Local frame width
 * @param local_h Local frame height
 * @return 0 on success, -1 on error
 *
 * The big view is letterboxed and captioned; the strip cells are captioned
 * and outlined by state - amber for pinned, blue for whoever is on the big
 * view, green while they are talking. Cell rectangles are kept so a click
 * can be turned back into a participant; see video_display_hit_test.
 */
int video_display_render_speaker(VideoDisplay *disp,
                                 const VideoTile *main_tile,
                                 const VideoTile *tiles, int ntiles,
                                 const uint8_t *local_yuv,
                                 int local_w, int local_h);

/**
 * @brief Which strip cell a click landed in
 * @param disp Display context
 * @param x Pointer x, in window coordinates
 * @param y Pointer y, in window coordinates
 * @return index into the tiles array of the last render, or -1
 */
int video_display_hit_test(VideoDisplay *disp, float x, float y);

/**
 * @brief Set RTT value to display as overlay on video
 * @param disp Display context
 * @param rtt_ms Round-trip time in milliseconds
 */
void video_display_set_rtt(VideoDisplay *disp, uint32_t rtt_ms);

/**
 * @brief Close display and free resources
 * @param disp Display context (safe to pass NULL)
 */
void video_display_close(VideoDisplay *disp);

#endif /* VIDEO_DISPLAY_H */
