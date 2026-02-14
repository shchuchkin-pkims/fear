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
 * @brief Close display and free resources
 * @param disp Display context (safe to pass NULL)
 */
void video_display_close(VideoDisplay *disp);

#endif /* VIDEO_DISPLAY_H */
