/**
 * @file video_quality.h
 * @brief Adaptive video quality controller
 *
 * Monitors packet loss and RTT to dynamically adjust video quality.
 * Implements hysteresis to prevent oscillation between quality levels.
 *
 * Rules:
 * - Loss > 10%: immediately drop to Low
 * - Loss > 5%: drop one level
 * - RTT > 500ms: cap at Low
 * - RTT > 200ms: cap at Medium
 * - Loss < 1% sustained 5s: upgrade one level
 * - Min 5s between downgrades, 10s between upgrades
 */

#ifndef VIDEO_QUALITY_H
#define VIDEO_QUALITY_H

#include "video_types.h"
#include <stdint.h>

/** Minimum interval between downgrades (ms) */
#define QC_DOWNGRADE_COOLDOWN_MS  5000

/** Minimum interval between upgrades (ms) */
#define QC_UPGRADE_COOLDOWN_MS    10000

/** Duration of low-loss required before upgrade (ms) */
#define QC_UPGRADE_SUSTAINED_MS   5000

/** Loss threshold for immediate drop to Low (percent) */
#define QC_LOSS_CRITICAL          10.0f

/** Loss threshold for one-level downgrade (percent) */
#define QC_LOSS_HIGH              5.0f

/** Loss threshold below which upgrade is considered (percent) */
#define QC_LOSS_LOW               1.0f

/** RTT threshold for capping at Low (ms) */
#define QC_RTT_CRITICAL           500

/** RTT threshold for capping at Medium (ms) */
#define QC_RTT_HIGH               200

/** Stats reporting interval (ms) */
#define STATS_INTERVAL_MS         2000

/**
 * @struct QualityController
 * @brief State for adaptive quality control
 */
typedef struct {
    QualityLevel current_level;     /**< Current quality level */
    QualityLevel max_level;         /**< Maximum quality level allowed */
    int adaptive_enabled;           /**< 1 if adaptive quality is on */

    uint64_t last_downgrade_ms;     /**< Timestamp of last downgrade */
    uint64_t last_upgrade_ms;       /**< Timestamp of last upgrade */
    uint64_t low_loss_since_ms;     /**< Timestamp when loss first dropped below threshold */

    /* Stats tracking */
    uint32_t packets_sent;          /**< Packets sent since last report */
    uint32_t packets_received;      /**< Packets received (from peer report) */
    uint32_t packets_lost;          /**< Packets lost (from peer report) */
    uint32_t rtt_ms;                /**< Current RTT estimate */
    uint64_t last_stats_time_ms;    /**< Timestamp of last stats exchange */

    /* Custom parameters (used when current_level == QUALITY_CUSTOM) */
    VideoQualityPreset custom;      /**< User-specified custom preset */
} QualityController;

/**
 * @brief Initialize quality controller
 * @param qc Pointer to QualityController
 * @param initial_level Starting quality level
 * @param adaptive 1 to enable adaptive quality, 0 for manual
 */
void quality_init(QualityController *qc, QualityLevel initial_level, int adaptive);

/**
 * @brief Set custom quality parameters
 * @param qc Quality controller
 * @param width Frame width
 * @param height Frame height
 * @param fps Framerate
 * @param bitrate_kbps Bitrate in kbps
 */
void quality_set_custom(QualityController *qc, int width, int height,
                        int fps, int bitrate_kbps);

/**
 * @brief Get current quality preset parameters
 * @param qc Quality controller
 * @return Pointer to current preset (valid until next quality change)
 */
const VideoQualityPreset *quality_get_preset(const QualityController *qc);

/**
 * @brief Update controller with received stats from peer
 * @param qc Quality controller
 * @param stats Stats payload from peer
 * @param now_ms Current time in milliseconds
 * @return 1 if quality level changed, 0 otherwise
 */
int quality_update(QualityController *qc, const StatsPayload *stats, uint64_t now_ms);

/**
 * @brief Check if it's time to send a stats report
 * @param qc Quality controller
 * @param now_ms Current time in milliseconds
 * @return 1 if stats should be sent now, 0 otherwise
 */
int quality_should_send_stats(QualityController *qc, uint64_t now_ms);

/**
 * @brief Build a stats payload to send to peer
 * @param qc Quality controller
 * @param out Stats payload to fill
 */
void quality_build_stats(QualityController *qc, StatsPayload *out);

/**
 * @brief Record that a packet was sent (for loss tracking)
 * @param qc Quality controller
 */
void quality_record_sent(QualityController *qc);

/**
 * @brief Record packets received from peer stats report
 * @param qc Quality controller
 * @param received Number of packets received by peer
 * @param lost Number of packets lost by peer
 */
void quality_record_peer_stats(QualityController *qc, uint32_t received, uint32_t lost);

#endif /* VIDEO_QUALITY_H */
