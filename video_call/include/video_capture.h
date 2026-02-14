/**
 * @file video_capture.h
 * @brief Camera capture API using FFmpeg libavdevice
 *
 * Provides camera enumeration and frame capture for F.E.A.R. video calls.
 * Uses V4L2 on Linux and dshow on Windows.
 */

#ifndef VIDEO_CAPTURE_H
#define VIDEO_CAPTURE_H

#include "video_types.h"
#include <stdint.h>

/** Opaque capture context */
typedef struct VideoCapture VideoCapture;

/**
 * @brief List available camera devices to stdout
 * @return 0 on success, -1 on error
 */
int video_capture_list_devices(void);

/**
 * @brief Open camera device and begin capturing
 * @param cap Pointer to receive allocated capture context
 * @param device Device path (e.g., "/dev/video0") or NULL for default
 * @param width Desired capture width
 * @param height Desired capture height
 * @param fps Desired capture framerate
 * @return 0 on success, -1 on error
 */
int video_capture_open(VideoCapture **cap, const char *device,
                       int width, int height, int fps);

/**
 * @brief Read one frame from camera
 * @param cap Capture context
 * @param yuv_out Output buffer for YUV420P data (must be width*height*3/2 bytes)
 * @param max_size Maximum output buffer size
 * @return Number of bytes written to yuv_out, or -1 on error
 *
 * Blocks until a frame is available. Automatically converts from
 * camera's native format to YUV420P.
 */
int video_capture_read(VideoCapture *cap, uint8_t *yuv_out, int max_size);

/**
 * @brief Get current capture dimensions
 * @param cap Capture context
 * @param width Receives width (may differ from requested)
 * @param height Receives height (may differ from requested)
 */
void video_capture_get_size(VideoCapture *cap, int *width, int *height);

/**
 * @brief Close camera and free resources
 * @param cap Capture context (safe to pass NULL)
 */
void video_capture_close(VideoCapture *cap);

#endif /* VIDEO_CAPTURE_H */
