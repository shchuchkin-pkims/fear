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
