/**
 * @file audio_ring.h
 * @brief PCM audio ring buffer for F.E.A.R. audio calls
 *
 * Implements a thread-safe circular buffer for audio frames.
 * Used to decouple audio capture from network transmission.
 */

#ifndef AUDIO_RING_H
#define AUDIO_RING_H

#include "audio_types.h"
#include <stddef.h>
#include <stdint.h>

/* Platform-specific includes for mutex */
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <stdatomic.h>

/**
 * @struct PcmRing
 * @brief Thread-safe circular buffer for 16-bit PCM audio frames
 *
 * Stores fixed-size audio frames with synchronized access.
 * Uses mutex for thread safety and atomic counter for lock-free reads.
 */
typedef struct {
    int16_t *buf;           /**< Buffer storage (frames * SAMPLES_PER_FRAME) */
    size_t frames_cap;      /**< Maximum number of frames */
    size_t rd;              /**< Current read position (frame index) */
    size_t wr;              /**< Current write position (frame index) */
    atomic_size_t count;    /**< Number of frames currently in buffer (atomic) */
#ifdef _WIN32
    CRITICAL_SECTION lock;  /**< Windows critical section for synchronization */
#else
    pthread_mutex_t lock;   /**< POSIX mutex for synchronization */
#endif
} PcmRing;

/**
 * @brief Initialize PCM ring buffer
 * @param r Pointer to PcmRing structure
 * @param frames_cap Maximum number of frames to store
 * @return 0 on success, -1 on allocation failure
 * @note Caller must call pcmring_free() when done
 */
int pcmring_init(PcmRing *r, size_t frames_cap);

/**
 * @brief Free ring buffer memory
 * @param r Pointer to PcmRing structure
 * @note Safe to call even if init failed
 */
void pcmring_free(PcmRing *r);

/**
 * @brief Push one audio frame into ring buffer
 * @param r Pointer to PcmRing structure
 * @param frame PCM data (SAMPLES_PER_FRAME samples)
 * @return 0 on success, -1 if buffer full
 * @note Drops frame if buffer is full (no blocking)
 */
int pcmring_push(PcmRing *r, const int16_t *frame);

/**
 * @brief Pop one audio frame from ring buffer
 * @param r Pointer to PcmRing structure
 * @param out_frame Output buffer (must hold SAMPLES_PER_FRAME samples)
 * @return 0 on success, -1 if buffer empty
 * @note Returns silence (zeros) if buffer is empty
 */
int pcmring_pop(PcmRing *r, int16_t *out_frame);

#endif /* AUDIO_RING_H */
