/**
 * @file video_types.h
 * @brief Common types and constants for F.E.A.R. video call module
 *
 * Defines packet types, quality presets, fragment structures,
 * and protocol constants for encrypted video calling.
 */

#ifndef VIDEO_TYPES_H
#define VIDEO_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET socket_t;
#define CLOSE_SOCKET closesocket
#define CLOSESOCK closesocket
#define SOCK_ERR SOCKET_ERROR
#else
typedef int socket_t;
#define CLOSE_SOCKET close
#define CLOSESOCK close
#define SOCK_ERR -1
#endif

/* ===== Packet Type Tags (first byte of UDP packet) ===== */

/** Audio data packet */
#define PKT_TYPE_AUDIO      0x01

/** Video fragment packet */
#define PKT_TYPE_VIDEO_FRAG 0x02

/** Quality/stats report packet */
#define PKT_TYPE_STATS      0x04

/** HELLO handshake packet */
#define PKT_TYPE_HELLO      0x7F

/* ===== HELLO Handshake ===== */

/** Audio-only HELLO: [0x7F][prefix(4)] = 5 bytes */
#define HELLO_SIZE_AUDIO    5

/** Video HELLO: [0x7F][prefix(4)][flags(1)][width(2)][height(2)][fps(1)] = 11 bytes */
#define HELLO_SIZE_VIDEO    11

/** HELLO flag: video capability */
#define HELLO_FLAG_VIDEO    0x01

/** HELLO flag: audio capability */
#define HELLO_FLAG_AUDIO    0x02

/* ===== Encryption ===== */

/** AES-GCM key size (32 bytes / 256 bits) */
#define VIDEO_KEY_SIZE      32

/** AES-GCM nonce size (12 bytes / 96 bits) */
#define VIDEO_NONCE_SIZE    12

/** AES-GCM authentication tag size (16 bytes) */
#define VIDEO_TAG_SIZE      16

/** Nonce prefix length (4 bytes, sender-specific) */
#define NONCE_PREFIX_LEN    4

/** KDF context for audio sub-key derivation */
#define KDF_CONTEXT_AUDIO   "fearaudi"

/** KDF context for video sub-key derivation */
#define KDF_CONTEXT_VIDEO   "fearvide"

/** KDF sub-key ID for audio */
#define KDF_SUBKEY_AUDIO    1

/** KDF sub-key ID for video */
#define KDF_SUBKEY_VIDEO    2

/* ===== Network Protocol ===== */

/** Maximum UDP packet size */
#define MAX_PACKET_SIZE     4096

/** UDP receive buffer size */
#define UDP_RECV_BUFSZ      1500

/* ===== Audio Configuration (reused from audio_call) ===== */

/** Sample rate for audio processing (48 kHz) */
#define SAMPLE_RATE         48000

/** Opus frame duration in milliseconds */
#define FRAME_DURATION_MS   20

/** Samples per frame (48000 * 20ms / 1000 = 960) */
#define SAMPLES_PER_FRAME   (SAMPLE_RATE * FRAME_DURATION_MS / 1000)

/** Number of audio channels (1 = mono) */
#define CHANNELS            1

/** Maximum Opus encoded frame size */
#define MAX_OPUS_FRAME      4000

/** PCM ring buffer capacity in frames */
#define PCM_RING_CAPACITY   256

/** Playout buffer threshold before playback starts */
#define PLAYOUT_BUFFER_FRAMES 6

/* ===== Video Fragmentation ===== */

/** Maximum fragment payload size (bytes of VP8 data per fragment) */
#define FRAG_MAX_PAYLOAD    1200

/** Fragment header size: frame_id(4)+frag_index(2)+total_frags(2)+frag_size(2)+reserved(2) */
#define FRAG_HEADER_SIZE    12

/** Maximum number of fragments per frame (ceil(150KB / 1200)) */
#define FRAG_MAX_PER_FRAME  128

/** Frame reassembly timeout in milliseconds */
#define FRAG_TIMEOUT_MS     500

/** Maximum concurrent pending frames */
#define FRAG_MAX_PENDING    8

/* ===== Video Quality Presets ===== */

/** Quality level enumeration */
typedef enum {
    QUALITY_LOW    = 0,
    QUALITY_MEDIUM = 1,
    QUALITY_HIGH   = 2,
    QUALITY_CUSTOM = 3
} QualityLevel;

/** Video quality preset parameters */
typedef struct {
    int width;          /**< Frame width in pixels */
    int height;         /**< Frame height in pixels */
    int fps;            /**< Target frames per second */
    int bitrate_kbps;   /**< Target bitrate in kbps */
} VideoQualityPreset;

/** Predefined quality presets */
static const VideoQualityPreset QUALITY_PRESETS[] = {
    { 320,  240, 15,  200},   /* QUALITY_LOW */
    { 640,  480, 25,  500},   /* QUALITY_MEDIUM */
    {1280,  720, 30, 1500},   /* QUALITY_HIGH */
    {   0,    0,  0,    0}    /* QUALITY_CUSTOM (user-specified) */
};

/* ===== Fragment Header ===== */

/**
 * @struct FragHeader
 * @brief Header prepended to each video fragment before encryption
 *
 * Total size: 12 bytes. Encrypted together with fragment payload.
 */
typedef struct {
    uint32_t frame_id;      /**< Frame sequence number */
    uint16_t frag_index;    /**< Fragment index within frame (0-based) */
    uint16_t total_frags;   /**< Total fragments in this frame */
    uint16_t frag_size;     /**< Payload size in this fragment */
    uint16_t reserved;      /**< Reserved for future use (must be 0) */
} FragHeader;

/* ===== Stats Packet ===== */

/**
 * @struct StatsPayload
 * @brief Quality statistics exchanged between peers
 */
typedef struct {
    uint32_t packets_received;  /**< Total packets received since last report */
    uint32_t packets_lost;      /**< Total packets lost since last report */
    uint32_t rtt_ms;            /**< Estimated round-trip time in ms */
    uint32_t reserved;          /**< Reserved for future use */
} StatsPayload;

/* ===== Hub ===== */

/** Maximum hub participants */
#define MAX_HUB_CLIENTS     32

/** Hub participant timeout in seconds */
#define HUB_TIMEOUT_SEC     30

#endif /* VIDEO_TYPES_H */
