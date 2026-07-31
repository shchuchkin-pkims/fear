/**
 * @file common.h
 * @brief Common definitions and utilities for F.E.A.R. messenger
 *
 * Provides cross-platform abstractions, protocol constants, and utility
 * function declarations used throughout the client and server modules.
 */

#ifndef COMMON_H
#define COMMON_H

/* Platform-specific socket includes and type definitions */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;              /* Windows socket type */
#define close_socket closesocket    /* Windows close function */
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int sock_t;                 /* POSIX socket type */
#define close_socket close          /* POSIX close function */
#endif

#include <stdint.h>
#include <stddef.h>

/* ===== Protocol Constants ===== */

/** Maximum room name length (including null terminator) */
#define MAX_ROOM 256

/** Maximum user name length (including null terminator) */
#define MAX_NAME 256

/** Maximum filename length for file transfers */
#define MAX_FILENAME 1024

/** Maximum frame size (messages larger than this are rejected) */
#define MAX_FRAME 65536

/** File transfer chunk size (8 KB chunks) */
#define FILE_CHUNK_SIZE 8192

/** Default server port if not specified */
#define DEFAULT_PORT 8888

/** Maximum concurrent clients per server */
#define MAX_CLIENTS 100

/* ===== Message Types ===== */

/**
 * @brief Message type identifiers for the protocol
 *
 * Each message frame includes a 1-byte type field to distinguish
 * between different kinds of messages.
 */
typedef enum {
    MSG_TYPE_TEXT = 0,              /**< Regular encrypted text message */
    MSG_TYPE_FILE_START = 1,        /**< File transfer start (metadata) */
    MSG_TYPE_FILE_CHUNK = 2,        /**< File transfer data chunk */
    MSG_TYPE_FILE_END = 3,          /**< File transfer completion */
    MSG_TYPE_USER_LIST = 4,         /**< Room participant list (from server) */
    MSG_TYPE_SIGNED_TEXT = 5,       /**< Signed text: [pk(32)][sig(64)][message] */
    MSG_TYPE_SIGNED_FILE_START = 6, /**< Signed file start */
    MSG_TYPE_SIGNED_FILE_CHUNK = 7, /**< Signed file chunk */
    MSG_TYPE_SIGNED_FILE_END = 8,   /**< Signed file end */
    MSG_TYPE_IDENTITY_ANNOUNCE = 9, /**< Identity announcement: [pk(32)][sig(64)] */
    MSG_TYPE_KEY_REQUEST  = 15,     /**< ECDH key request: [x25519_pk(32)] (zero nonce service msg) */
    MSG_TYPE_KEY_RESPONSE = 16,     /**< ECDH key response: [target_name_len(2)][target_name][responder_pk(32)][box_nonce(24)][crypto_box(room_key)(48)] */
    MSG_TYPE_MEDIA_RELAY  = 17,     /**< Media relay: payload is raw encrypted media packet (audio/video/hello) */
    /* ===== Phase B-2: handle registry ===== */
    MSG_TYPE_REGISTER_HANDLE  = 20, /**< Client → Server: claim a handle.
                                          Payload: [pk(32)][sig(64)][handle_len(1)][handle UTF-8].
                                          Server replies with REGISTER_HANDLE_RESULT. */
    MSG_TYPE_LOOKUP_HANDLE    = 21, /**< Client → Server: ask which pk owns a handle.
                                          Payload: [handle_len(1)][handle UTF-8].
                                          Server replies with LOOKUP_HANDLE_RESULT. */
    MSG_TYPE_HANDLE_RESULT    = 22, /**< Server → Client.
                                          Payload: [status(1)][reason_len(1)][reason][pk(0 or 32)].
                                          status: 0=ok, 1=conflict, 2=invalid, 3=server_error.
                                          For lookup, pk is the owner (status=0) or absent (status=1). */
    /* ===== Phase B-3: per-user encrypted blob storage ===== */
    MSG_TYPE_BLOB_PUT         = 23, /**< Client → Server: write a blob.
                                          Payload: [pk(32)][sig(64)][type_len(1)][type][cipher_len(4)][cipher].
                                          sig is Ed25519(type || cipher) — proves owner of pk.
                                          Server replies with BLOB_RESULT (no payload-cipher field). */
    MSG_TYPE_BLOB_GET         = 24, /**< Client → Server: read a blob.
                                          Payload: [pk(32)][sig(64)][type_len(1)][type].
                                          sig is Ed25519(challenge || type) under pk's secret
                                          key, where challenge was obtained on this connection
                                          via BLOB_GET_CHALLENGE. Only the blob owner can read
                                          it (M10): even though blobs are encrypted client-side,
                                          unauthorized reads leak ciphertext and act as a
                                          presence oracle. Server replies with BLOB_RESULT
                                          (with payload-cipher when found). */
    MSG_TYPE_BLOB_RESULT      = 25, /**< Server → Client.
                                          Payload: [status(1)][reason_len(1)][reason][cipher_len(4)][cipher].
                                          status: 0=ok, 1=not_found, 2=invalid, 3=server_error.
                                          cipher_len + cipher present only on GET success. */
    /* ===== Phase B-7: reverse lookup of handle by pk ===== */
    MSG_TYPE_LOOKUP_HANDLE_BY_PK = 26, /**< Client → Server: which handle is registered for this pk?
                                          Payload: [pk(32)].
                                          Server replies with HANDLE_RESULT.
                                          status=0: payload is [0][reason_len(1)][reason][handle_len(1)][handle].
                                          status=1: pk has no registered handle on this server.
                                          Used by clients to detect a pre-existing registration after
                                          identity import (.fbk / QR) without forcing the user to guess
                                          their handle. */
    /* ===== Phase B-8: room probe + heartbeat ===== */
    MSG_TYPE_ROOM_INFO_REQUEST = 27, /**< Client → Server: how many members are in this room?
                                          Zero-nonce service msg. Room name is taken from the
                                          frame header (room_len/room fields). Payload empty.
                                          Server replies with ROOM_INFO_RESULT.
                                          Used by AUTO connect to skip the JOIN→timeout→CREATE
                                          dance when the room is empty. */
    MSG_TYPE_ROOM_INFO_RESULT  = 28, /**< Server → Client.
                                          Payload: [exists(1)][member_count(4 LE)].
                                          exists=1 if at least one non-media client is in the
                                          room; member_count is the same number (kept for future
                                          UI use). */
    MSG_TYPE_PING              = 29, /**< Client → Server: I'm alive.
                                          Zero-nonce service msg, empty payload. Server bumps
                                          last_seen and does not reply. Sent ~every 60s when
                                          the client is otherwise silent so the server's idle
                                          scan doesn't kick the connection. */
    /* ===== Phase C: call signalling ===== */
    MSG_TYPE_CALL_INVITE      = 32, /**< Room member -> room: I am starting a call.
                                          Encrypted like any chat message, so the relay can
                                          neither read nor forge one, and every member of the
                                          room receives it - which is what makes this work for
                                          group calls rather than only for two parties.
                                          Payload: see identity/call_invite.h. Carries the
                                          call_id every media key is bound to; without it two
                                          peers have no way to agree on one, and deriving it
                                          from the room key would make it identical for every
                                          call in that room. */
    /* ===== M10 (audit 2026-07): authorized blob reads ===== */
    MSG_TYPE_BLOB_GET_CHALLENGE = 30, /**< Client → Server: request a one-shot nonce that
                                          authorizes a single BLOB_GET on this connection.
                                          Empty payload. Server replies with
                                          BLOB_CHALLENGE_RESULT. */
    MSG_TYPE_BLOB_CHALLENGE_RESULT = 31, /**< Server → Client: [challenge(32)]. The nonce is
                                          random, bound to the connection and consumed by the
                                          next BLOB_GET (whether the signature verifies or
                                          not). */
} message_type_t;

/* ===== Cryptographic Constants ===== */

/**
 * AES-256-GCM parameters (chosen for Android compatibility)
 *
 * Using AES-GCM instead of XChaCha20-Poly1305 for better hardware
 * acceleration support on mobile platforms.
 */

/** AES-256-GCM key size (32 bytes / 256 bits) */
#define CRYPTO_AEAD_AES256GCM_KEYBYTES 32

/** AES-256-GCM nonce size (12 bytes / 96 bits) */
#define CRYPTO_AEAD_AES256GCM_NPUBBYTES 12

/** AES-256-GCM authentication tag size (16 bytes / 128 bits) */
#define CRYPTO_AEAD_AES256GCM_ABYTES 16

/* Shorter aliases to avoid conflicts with libsodium headers */
#define CRYPTO_KEYBYTES CRYPTO_AEAD_AES256GCM_KEYBYTES
#define CRYPTO_NPUBBYTES CRYPTO_AEAD_AES256GCM_NPUBBYTES
#define CRYPTO_ABYTES CRYPTO_AEAD_AES256GCM_ABYTES

/* ===== UDP Relay Constants ===== */

/** Magic byte for UDP relay registration packet */
#define UDP_REG_MAGIC 0xFE

/* ===== Function Declarations ===== */

/* Binary I/O helpers (little-endian) */
uint16_t rd_u16(const uint8_t *p);
void wr_u16(uint8_t *p, uint16_t v);
uint32_t rd_u32(const uint8_t *p);
void wr_u32(uint8_t *p, uint32_t v);

/* Error handling */
void die(const char *msg);

/* Network I/O with complete transfer guarantees */
int recv_all(sock_t fd, void *buf, size_t len);
int send_all(sock_t fd, const void *buf, size_t len);

/* Base64 encoding/decoding (URL-safe, no padding) */
char *b64_encode(const uint8_t *buf, size_t len);
int b64_decode(const char *b64, uint8_t *out, size_t outlen);

/* Data integrity */
uint32_t crc32(const uint8_t *data, size_t len);

/* AES-256-GCM encryption/decryption (AEAD) */
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *ciphertext, unsigned long long *ciphertext_len);

int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *additional_data, size_t additional_data_len,
                   const uint8_t *nonce, const uint8_t *key,
                   uint8_t *plaintext, unsigned long long *plaintext_len);

#endif /* COMMON_H */