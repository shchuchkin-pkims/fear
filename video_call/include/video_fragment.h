/**
 * @file video_fragment.h
 * @brief UDP fragmentation and reassembly for video frames
 *
 * Video frames (10-100KB) exceed UDP MTU (~1400 bytes).
 * This module splits frames into fragments for transmission
 * and reassembles them on the receiving end with bitmask tracking.
 *
 * Fragment wire format (before encryption):
 *   FragHeader(12 bytes) + VP8 payload (up to FRAG_MAX_PAYLOAD bytes)
 *
 * Each fragment is independently encrypted with AES-256-GCM.
 */

#ifndef VIDEO_FRAGMENT_H
#define VIDEO_FRAGMENT_H

#include "video_types.h"
#include <stdint.h>
#include <stddef.h>

/* ===== Fragmentation (sender side) ===== */

/**
 * @struct FragList
 * @brief List of fragments produced from one video frame
 */
typedef struct {
    int count;                                      /**< Number of fragments */
    int sizes[FRAG_MAX_PER_FRAME];                  /**< Size of each fragment (header + payload) */
    uint8_t data[FRAG_MAX_PER_FRAME][FRAG_HEADER_SIZE + FRAG_MAX_PAYLOAD]; /**< Fragment data */
} FragList;

/**
 * @brief Split a video frame into fragments
 * @param frame_data Encoded VP8 frame data
 * @param frame_size Size of frame data in bytes
 * @param frame_id Frame sequence number
 * @param out Pointer to FragList to fill
 * @return Number of fragments produced, or -1 on error
 */
int video_fragment_split(const uint8_t *frame_data, int frame_size,
                         uint32_t frame_id, FragList *out);

/* ===== Reassembly (receiver side) ===== */

/**
 * @struct FragAssembly
 * @brief State for reassembling one frame from fragments
 */
typedef struct {
    uint32_t frame_id;                  /**< Frame ID being assembled */
    uint16_t total_frags;               /**< Expected total fragments */
    uint16_t received_count;            /**< Fragments received so far */
    uint8_t received[FRAG_MAX_PER_FRAME]; /**< Bitmask: 1 if fragment received */
    uint8_t *frame_buf;                 /**< Reassembled frame data buffer */
    int frame_buf_size;                 /**< Allocated size of frame buffer */
    int frame_data_size;                /**< Actual assembled data size */
    uint64_t start_time_ms;             /**< Timestamp when first fragment arrived */
    int active;                         /**< 1 if slot is in use, 0 if free */
} FragAssembly;

/**
 * @struct FragReceiver
 * @brief Manages reassembly of multiple concurrent frames
 */
typedef struct {
    FragAssembly slots[FRAG_MAX_PENDING];  /**< Pending frame slots */
    uint32_t last_completed_frame_id;       /**< ID of last successfully completed frame */
} FragReceiver;

/**
 * @brief Initialize fragment receiver
 * @param recv Pointer to FragReceiver
 */
void video_frag_receiver_init(FragReceiver *recv);

/**
 * @brief Process one received fragment
 * @param recv Fragment receiver state
 * @param frag_data Raw fragment data (FragHeader + payload), already decrypted
 * @param frag_len Length of fragment data
 * @param frame_out Output buffer for completed frame
 * @param max_frame_out Maximum output buffer size
 * @param out_frame_id Receives frame_id if frame completed
 * @return Size of completed frame if frame is now complete, 0 if more fragments needed, -1 on error
 */
int video_frag_receiver_push(FragReceiver *recv,
                             const uint8_t *frag_data, int frag_len,
                             uint8_t *frame_out, int max_frame_out,
                             uint32_t *out_frame_id);

/**
 * @brief Expire timed-out incomplete frames
 * @param recv Fragment receiver state
 * @param now_ms Current time in milliseconds
 */
void video_frag_receiver_expire(FragReceiver *recv, uint64_t now_ms);

/**
 * @brief Free all resources held by fragment receiver
 * @param recv Fragment receiver state
 */
void video_frag_receiver_free(FragReceiver *recv);

/**
 * @brief Get current time in milliseconds (utility)
 * @return Current time in ms
 */
uint64_t video_time_ms(void);

#endif /* VIDEO_FRAGMENT_H */
