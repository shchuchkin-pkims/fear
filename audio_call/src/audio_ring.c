/**
 * @file audio_ring.c
 * @brief PCM ring buffer implementation for F.E.A.R. audio calls
 *
 * Thread-safe circular buffer for audio frames using mutex locking
 * and atomic counters for efficient synchronization.
 */

#include "audio_ring.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Initialize PCM ring buffer
 *
 * Allocates memory for buffer and initializes synchronization primitives.
 *
 * @param r Pointer to PcmRing structure
 * @param frames_cap Maximum number of frames to store
 * @return 0 on success, -1 on allocation failure
 */
int pcmring_init(PcmRing *r, size_t frames_cap) {
    memset(r, 0, sizeof(*r));
    r->frames_cap = frames_cap;

    /* Allocate buffer for frames */
    r->buf = (int16_t*)malloc(frames_cap * SAMPLES_PER_FRAME * sizeof(int16_t));
    if (!r->buf) {
        return -1;
    }

    /* Initialize platform-specific mutex */
#ifdef _WIN32
    InitializeCriticalSection(&r->lock);
#else
    pthread_mutex_init(&r->lock, NULL);
#endif

    /* Initialize atomic counter and positions */
    atomic_init(&r->count, 0);
    r->rd = r->wr = 0;

    return 0;
}

/**
 * @brief Free ring buffer resources
 *
 * Releases allocated memory and destroys synchronization primitives.
 *
 * @param r Pointer to PcmRing structure
 * @note Safe to call even if init failed
 */
void pcmring_free(PcmRing *r) {
    if (!r) {
        return;
    }

    /* Free buffer memory */
    if (r->buf) {
        free(r->buf);
    }

    /* Destroy platform-specific mutex */
#ifdef _WIN32
    DeleteCriticalSection(&r->lock);
#else
    pthread_mutex_destroy(&r->lock);
#endif

    /* Clear structure */
    memset(r, 0, sizeof(*r));
}

/**
 * @brief Push one audio frame into ring buffer
 *
 * If buffer is full, drops oldest frame to make room (FIFO eviction).
 * Thread-safe operation using mutex.
 *
 * @param r Pointer to PcmRing structure
 * @param frame PCM data (SAMPLES_PER_FRAME samples)
 * @return Always returns 0 (never fails)
 *
 * @note Overwrites oldest frame if buffer is full
 */
int pcmring_push(PcmRing *r, const int16_t *frame) {
    /* Acquire lock for thread safety */
#ifdef _WIN32
    EnterCriticalSection(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif

    /* If buffer is full, drop oldest frame */
    if (atomic_load(&r->count) == r->frames_cap) {
        r->rd = (r->rd + 1) % r->frames_cap;
        atomic_fetch_sub(&r->count, 1);
    }

    /* Copy frame data to write position */
    memcpy(&r->buf[r->wr * SAMPLES_PER_FRAME], frame,
           SAMPLES_PER_FRAME * sizeof(int16_t));

    /* Advance write pointer (circular) */
    r->wr = (r->wr + 1) % r->frames_cap;

    /* Increment frame count */
    atomic_fetch_add(&r->count, 1);

    /* Release lock */
#ifdef _WIN32
    LeaveCriticalSection(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif

    return 0;
}

/**
 * @brief Pop one audio frame from ring buffer
 *
 * Retrieves and removes oldest frame from buffer.
 * Thread-safe operation using mutex.
 *
 * @param r Pointer to PcmRing structure
 * @param out_frame Output buffer (must hold SAMPLES_PER_FRAME samples)
 * @return 0 on success, -1 if buffer empty
 *
 * @note Double-checks empty condition after acquiring lock (race prevention)
 */
int pcmring_pop(PcmRing *r, int16_t *out_frame) {
    /* Quick check without lock (optimization) */
    if (atomic_load(&r->count) == 0) {
        return -1;
    }

    /* Acquire lock for thread safety */
#ifdef _WIN32
    EnterCriticalSection(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif

    /* Double-check after acquiring lock (avoid race condition) */
    if (atomic_load(&r->count) == 0) {
#ifdef _WIN32
        LeaveCriticalSection(&r->lock);
#else
        pthread_mutex_unlock(&r->lock);
#endif
        return -1;
    }

    /* Copy frame data from read position */
    memcpy(out_frame, &r->buf[r->rd * SAMPLES_PER_FRAME],
           SAMPLES_PER_FRAME * sizeof(int16_t));

    /* Advance read pointer (circular) */
    r->rd = (r->rd + 1) % r->frames_cap;

    /* Decrement frame count */
    atomic_fetch_sub(&r->count, 1);

    /* Release lock */
#ifdef _WIN32
    LeaveCriticalSection(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif

    return 0;
}
