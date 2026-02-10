/**
 * @file audio_types.h
 * @brief Common types and constants for F.E.A.R. audio call module
 *
 * Defines platform-independent types, buffer sizes, and protocol constants
 * used throughout the audio calling system.
 */

#ifndef AUDIO_TYPES_H
#define AUDIO_TYPES_H

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

/* ===== Audio Configuration ===== */

/** Sample rate for audio processing (48 kHz - Opus recommended) */
#define SAMPLE_RATE 48000

/** Opus frame duration in milliseconds */
#define FRAME_DURATION_MS 20

/** Samples per frame (48000 Hz * 20ms / 1000) */
#define SAMPLES_PER_FRAME (SAMPLE_RATE * FRAME_DURATION_MS / 1000)

/** Number of audio channels (1 = mono) */
#define CHANNELS 1

/* ===== Network Protocol ===== */

/** Maximum UDP packet size for audio data */
#define MAX_PACKET_SIZE 4096

/** Hello packet magic bytes for handshake */
#define HELLO_MAGIC 0xFEARAUDIO

/** Protocol version number */
#define PROTOCOL_VERSION 1

/* ===== Buffer Sizes ===== */

/** PCM ring buffer capacity in frames */
#define PCM_RING_CAPACITY 256

/** Maximum Opus encoded frame size */
#define MAX_OPUS_FRAME 4000

/** Maximum number of hub participants */
#define MAX_HUB_CLIENTS 32

/** Hub participant timeout in seconds */
#define HUB_TIMEOUT_SEC 30

/* ===== Encryption ===== */

/** AES-GCM key size (32 bytes / 256 bits) */
#define AUDIO_KEY_SIZE 32

/** AES-GCM nonce size (12 bytes / 96 bits) */
#define AUDIO_NONCE_SIZE 12

/** AES-GCM authentication tag size (16 bytes) */
#define AUDIO_TAG_SIZE 16

#endif /* AUDIO_TYPES_H */
