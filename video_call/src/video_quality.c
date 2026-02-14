/**
 * @file video_quality.c
 * @brief Adaptive video quality controller
 *
 * Monitors packet loss and RTT to dynamically adjust video quality.
 * Uses hysteresis to prevent oscillation between quality levels.
 */

#include "video_quality.h"
#include "video_fragment.h"  /* for video_time_ms() */
#include <string.h>
#include <stdio.h>

void quality_init(QualityController *qc, QualityLevel initial_level, int adaptive) {
    if (!qc) return;
    memset(qc, 0, sizeof(*qc));

    qc->current_level = initial_level;
    qc->max_level = QUALITY_HIGH;
    qc->adaptive_enabled = adaptive;
    qc->last_stats_time_ms = video_time_ms();
}

void quality_set_custom(QualityController *qc, int width, int height,
                        int fps, int bitrate_kbps) {
    if (!qc) return;
    qc->custom.width = width;
    qc->custom.height = height;
    qc->custom.fps = fps;
    qc->custom.bitrate_kbps = bitrate_kbps;
}

const VideoQualityPreset *quality_get_preset(const QualityController *qc) {
    if (!qc) return &QUALITY_PRESETS[QUALITY_MEDIUM];

    if (qc->current_level == QUALITY_CUSTOM) {
        return &qc->custom;
    }
    return &QUALITY_PRESETS[qc->current_level];
}

static float compute_loss_percent(const StatsPayload *stats) {
    uint32_t total = stats->packets_received + stats->packets_lost;
    if (total == 0) return 0.0f;
    return (float)stats->packets_lost * 100.0f / (float)total;
}

int quality_update(QualityController *qc, const StatsPayload *stats, uint64_t now_ms) {
    if (!qc || !stats || !qc->adaptive_enabled) return 0;
    if (qc->current_level == QUALITY_CUSTOM) return 0;

    float loss = compute_loss_percent(stats);
    uint32_t rtt = stats->rtt_ms;
    QualityLevel old_level = qc->current_level;

    /* Immediate drop to Low on critical loss */
    if (loss > QC_LOSS_CRITICAL) {
        if (qc->current_level != QUALITY_LOW &&
            (now_ms - qc->last_downgrade_ms) >= QC_DOWNGRADE_COOLDOWN_MS) {
            qc->current_level = QUALITY_LOW;
            qc->last_downgrade_ms = now_ms;
            qc->low_loss_since_ms = 0;
            printf("[quality] Critical loss %.1f%%, dropping to LOW\n", loss);
        }
    }
    /* Drop one level on high loss */
    else if (loss > QC_LOSS_HIGH) {
        if (qc->current_level > QUALITY_LOW &&
            (now_ms - qc->last_downgrade_ms) >= QC_DOWNGRADE_COOLDOWN_MS) {
            qc->current_level = (QualityLevel)(qc->current_level - 1);
            qc->last_downgrade_ms = now_ms;
            qc->low_loss_since_ms = 0;
            printf("[quality] High loss %.1f%%, downgrading to level %d\n",
                   loss, qc->current_level);
        }
    }
    /* Track sustained low loss for upgrade */
    else if (loss < QC_LOSS_LOW) {
        if (qc->low_loss_since_ms == 0) {
            qc->low_loss_since_ms = now_ms;
        }
    } else {
        qc->low_loss_since_ms = 0;
    }

    /* RTT-based caps */
    if (rtt > QC_RTT_CRITICAL && qc->current_level > QUALITY_LOW) {
        if ((now_ms - qc->last_downgrade_ms) >= QC_DOWNGRADE_COOLDOWN_MS) {
            qc->current_level = QUALITY_LOW;
            qc->last_downgrade_ms = now_ms;
            printf("[quality] RTT %u ms (critical), capping to LOW\n", rtt);
        }
    } else if (rtt > QC_RTT_HIGH && qc->current_level > QUALITY_MEDIUM) {
        if ((now_ms - qc->last_downgrade_ms) >= QC_DOWNGRADE_COOLDOWN_MS) {
            qc->current_level = QUALITY_MEDIUM;
            qc->last_downgrade_ms = now_ms;
            printf("[quality] RTT %u ms (high), capping to MEDIUM\n", rtt);
        }
    }

    /* Upgrade if low loss sustained */
    if (qc->low_loss_since_ms > 0 &&
        (now_ms - qc->low_loss_since_ms) >= QC_UPGRADE_SUSTAINED_MS &&
        qc->current_level < qc->max_level &&
        (now_ms - qc->last_upgrade_ms) >= QC_UPGRADE_COOLDOWN_MS &&
        rtt <= QC_RTT_HIGH) {
        qc->current_level = (QualityLevel)(qc->current_level + 1);
        qc->last_upgrade_ms = now_ms;
        qc->low_loss_since_ms = 0;
        printf("[quality] Low loss sustained, upgrading to level %d\n",
               qc->current_level);
    }

    return (qc->current_level != old_level) ? 1 : 0;
}

int quality_should_send_stats(QualityController *qc, uint64_t now_ms) {
    if (!qc) return 0;
    if ((now_ms - qc->last_stats_time_ms) >= STATS_INTERVAL_MS) {
        return 1;
    }
    return 0;
}

void quality_build_stats(QualityController *qc, StatsPayload *out) {
    if (!qc || !out) return;
    memset(out, 0, sizeof(*out));
    out->packets_received = qc->packets_received;
    out->packets_lost = qc->packets_lost;
    out->rtt_ms = qc->rtt_ms;

    /* Reset counters after building */
    qc->packets_sent = 0;
    qc->last_stats_time_ms = video_time_ms();
}

void quality_record_sent(QualityController *qc) {
    if (qc) qc->packets_sent++;
}

void quality_record_peer_stats(QualityController *qc, uint32_t received, uint32_t lost) {
    if (!qc) return;
    qc->packets_received = received;
    qc->packets_lost = lost;
}
