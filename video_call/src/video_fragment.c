/**
 * @file video_fragment.c
 * @brief UDP fragmentation and reassembly for video frames
 *
 * Splits large VP8 frames into MTU-safe fragments and reassembles
 * them on the receiver side using bitmask tracking.
 */

#include "video_fragment.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

/* ===== Utilities ===== */

uint64_t video_time_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/* ===== Serialization helpers ===== */

static void frag_header_write(uint8_t *buf, const FragHeader *h) {
    uint32_t fid = h->frame_id;
    buf[0] = (uint8_t)(fid >> 24);
    buf[1] = (uint8_t)(fid >> 16);
    buf[2] = (uint8_t)(fid >> 8);
    buf[3] = (uint8_t)(fid);

    buf[4] = (uint8_t)(h->frag_index >> 8);
    buf[5] = (uint8_t)(h->frag_index);

    buf[6] = (uint8_t)(h->total_frags >> 8);
    buf[7] = (uint8_t)(h->total_frags);

    buf[8] = (uint8_t)(h->frag_size >> 8);
    buf[9] = (uint8_t)(h->frag_size);

    buf[10] = 0;
    buf[11] = 0;
}

static void frag_header_read(const uint8_t *buf, FragHeader *h) {
    h->frame_id = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                  ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];

    h->frag_index = ((uint16_t)buf[4] << 8) | (uint16_t)buf[5];
    h->total_frags = ((uint16_t)buf[6] << 8) | (uint16_t)buf[7];
    h->frag_size = ((uint16_t)buf[8] << 8) | (uint16_t)buf[9];
    h->reserved = 0;
}

/* ===== Fragmentation (sender) ===== */

int video_fragment_split(const uint8_t *frame_data, int frame_size,
                         uint32_t frame_id, FragList *out) {
    if (!frame_data || frame_size <= 0 || !out) return -1;

    int total_frags = (frame_size + FRAG_MAX_PAYLOAD - 1) / FRAG_MAX_PAYLOAD;
    if (total_frags > FRAG_MAX_PER_FRAME) {
        fprintf(stderr, "video_fragment: frame too large (%d bytes, %d frags)\n",
                frame_size, total_frags);
        return -1;
    }

    out->count = total_frags;
    int offset = 0;

    for (int i = 0; i < total_frags; i++) {
        int payload_size = frame_size - offset;
        if (payload_size > FRAG_MAX_PAYLOAD) payload_size = FRAG_MAX_PAYLOAD;

        FragHeader hdr;
        hdr.frame_id = frame_id;
        hdr.frag_index = (uint16_t)i;
        hdr.total_frags = (uint16_t)total_frags;
        hdr.frag_size = (uint16_t)payload_size;
        hdr.reserved = 0;

        frag_header_write(out->data[i], &hdr);
        memcpy(out->data[i] + FRAG_HEADER_SIZE, frame_data + offset, payload_size);

        out->sizes[i] = FRAG_HEADER_SIZE + payload_size;
        offset += payload_size;
    }

    return total_frags;
}

/* ===== Reassembly (receiver) ===== */

void video_frag_receiver_init(FragReceiver *recv) {
    if (!recv) return;
    memset(recv, 0, sizeof(*recv));
}

static FragAssembly *find_or_create_slot(FragReceiver *recv, uint32_t frame_id,
                                          uint16_t total_frags) {
    /* Look for existing slot */
    for (int i = 0; i < FRAG_MAX_PENDING; i++) {
        if (recv->slots[i].active && recv->slots[i].frame_id == frame_id) {
            return &recv->slots[i];
        }
    }

    /* Skip frames older than last completed */
    if (frame_id <= recv->last_completed_frame_id && recv->last_completed_frame_id != 0) {
        return NULL;
    }

    /* Find free slot */
    for (int i = 0; i < FRAG_MAX_PENDING; i++) {
        if (!recv->slots[i].active) {
            FragAssembly *slot = &recv->slots[i];
            memset(slot, 0, sizeof(*slot));
            slot->frame_id = frame_id;
            slot->total_frags = total_frags;
            slot->received_count = 0;
            slot->active = 1;
            slot->start_time_ms = video_time_ms();

            /* Allocate frame buffer (max possible size) */
            slot->frame_buf_size = total_frags * FRAG_MAX_PAYLOAD;
            slot->frame_buf = (uint8_t *)calloc(1, slot->frame_buf_size);
            if (!slot->frame_buf) {
                slot->active = 0;
                return NULL;
            }
            slot->frame_data_size = 0;
            return slot;
        }
    }

    /* All slots full - evict oldest */
    uint64_t oldest_time = UINT64_MAX;
    int oldest_idx = 0;
    for (int i = 0; i < FRAG_MAX_PENDING; i++) {
        if (recv->slots[i].start_time_ms < oldest_time) {
            oldest_time = recv->slots[i].start_time_ms;
            oldest_idx = i;
        }
    }

    FragAssembly *slot = &recv->slots[oldest_idx];
    free(slot->frame_buf);
    memset(slot, 0, sizeof(*slot));
    slot->frame_id = frame_id;
    slot->total_frags = total_frags;
    slot->active = 1;
    slot->start_time_ms = video_time_ms();
    slot->frame_buf_size = total_frags * FRAG_MAX_PAYLOAD;
    slot->frame_buf = (uint8_t *)calloc(1, slot->frame_buf_size);
    if (!slot->frame_buf) {
        slot->active = 0;
        return NULL;
    }
    return slot;
}

int video_frag_receiver_push(FragReceiver *recv,
                             const uint8_t *frag_data, int frag_len,
                             uint8_t *frame_out, int max_frame_out,
                             uint32_t *out_frame_id) {
    if (!recv || !frag_data || frag_len < FRAG_HEADER_SIZE || !frame_out) return -1;

    FragHeader hdr;
    frag_header_read(frag_data, &hdr);

    if (hdr.frag_index >= hdr.total_frags || hdr.total_frags == 0) return -1;
    if (hdr.total_frags > FRAG_MAX_PER_FRAME) return -1;
    if ((int)hdr.frag_size != frag_len - FRAG_HEADER_SIZE) return -1;

    FragAssembly *slot = find_or_create_slot(recv, hdr.frame_id, hdr.total_frags);
    if (!slot) return 0; /* Stale frame, skip */

    /* Check for duplicate */
    if (slot->received[hdr.frag_index]) return 0;

    /* Place fragment data into frame buffer at correct offset */
    int offset = hdr.frag_index * FRAG_MAX_PAYLOAD;
    if (offset + hdr.frag_size > slot->frame_buf_size) return -1;

    memcpy(slot->frame_buf + offset, frag_data + FRAG_HEADER_SIZE, hdr.frag_size);
    slot->received[hdr.frag_index] = 1;
    slot->received_count++;

    /* Track actual data size: for last fragment, use actual position */
    int end = offset + hdr.frag_size;
    if (end > slot->frame_data_size) {
        slot->frame_data_size = end;
    }

    /* Check if frame is complete */
    if (slot->received_count == slot->total_frags) {
        if (slot->frame_data_size > max_frame_out) {
            /* Frame too large for output buffer */
            slot->active = 0;
            free(slot->frame_buf);
            slot->frame_buf = NULL;
            return -1;
        }

        memcpy(frame_out, slot->frame_buf, slot->frame_data_size);
        int result = slot->frame_data_size;
        if (out_frame_id) *out_frame_id = slot->frame_id;

        recv->last_completed_frame_id = slot->frame_id;
        slot->active = 0;
        free(slot->frame_buf);
        slot->frame_buf = NULL;

        return result;
    }

    return 0; /* More fragments needed */
}

void video_frag_receiver_expire(FragReceiver *recv, uint64_t now_ms) {
    if (!recv) return;

    for (int i = 0; i < FRAG_MAX_PENDING; i++) {
        if (recv->slots[i].active &&
            (now_ms - recv->slots[i].start_time_ms) > FRAG_TIMEOUT_MS) {
            recv->slots[i].active = 0;
            free(recv->slots[i].frame_buf);
            recv->slots[i].frame_buf = NULL;
        }
    }
}

void video_frag_receiver_free(FragReceiver *recv) {
    if (!recv) return;

    for (int i = 0; i < FRAG_MAX_PENDING; i++) {
        if (recv->slots[i].frame_buf) {
            free(recv->slots[i].frame_buf);
            recv->slots[i].frame_buf = NULL;
        }
        recv->slots[i].active = 0;
    }
}
