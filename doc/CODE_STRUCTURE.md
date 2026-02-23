# Code Structure Guide

**Version:** 0.4.3

---

## Module Organization

### 1. Client-Console (`client-console/`)

Core messaging: console client, server, and CLI utilities.

```
client-console/
├── include/
│   ├── common.h      # Protocol constants, crypto wrappers, I/O helpers
│   ├── network.h     # TCP connection/listen abstractions
│   ├── client.h      # Client interface (connect modes, ECDH, identity)
│   └── server.h      # Server interface (relay, room management)
└── src/
    ├── main.c        # CLI entry point, argument parsing
    ├── common.c      # Binary I/O, Base64, AES-GCM, CRC32
    ├── network.c     # TCP dial/listen, cross-platform sockets
    ├── client.c      # Client logic: messaging, file transfer, ECDH, identity
    └── server.c      # Server logic: relay, room management, user lists
```

**Key responsibilities:**

- **common.c** — Little-endian I/O (`rd_u16`/`wr_u16`/`rd_u32`/`wr_u32`), `send_all`/`recv_all`, Base64 (URL-safe, RFC 4648), AES-256-GCM encrypt/decrypt, CRC32
- **network.c** — `dial_tcp(host, port)`, `server_listen(port)`, cross-platform socket init
- **client.c** — Room connection (3 modes: `--create`, `--join`, manual key), ECDH key exchange (MSG_TYPE_KEY_REQUEST/KEY_RESPONSE), Ed25519 identity (TOFU), file transfer, user list
- **server.c** — Accept connections, broadcast to room, enforce unique names, relay service messages (USER_LIST, KEY_REQUEST/KEY_RESPONSE), TCP media relay, TCP keepalive for dead connection detection

### 2. Video Call (`video_call/`)

Encrypted P2P video + audio over UDP.

```
video_call/
├── include/
│   ├── video_types.h      # Constants, packet types, quality presets
│   ├── video_capture.h    # Camera capture interface
│   ├── video_codec.h      # VP8 encoder/decoder interface
│   ├── video_display.h    # SDL3 display interface
│   ├── video_fragment.h   # UDP fragmentation/reassembly
│   └── video_quality.h    # Adaptive bitrate controller
└── src/
    ├── video_call.c       # Main orchestration, threads, AES-GCM, HELLO
    ├── video_capture.c    # FFmpeg camera (dshow/V4L2), MJPEG, sws_scale
    ├── video_codec.c      # VP8 encode/decode via libavcodec
    ├── video_display.c    # SDL3 YUV420P rendering
    ├── video_fragment.c   # 1200-byte fragment split/reassemble
    └── video_quality.c    # LOW/MEDIUM/HIGH presets, bitrate control
```

**Video pipeline:**
```
Camera (FFmpeg) → sws_scale → VP8 encode → Fragment (1200B)
  → AES-256-GCM encrypt → UDP send
  → UDP recv → AES-256-GCM decrypt → Reassemble
  → VP8 decode → SDL3 display (YUV420P)
```

### 3. Audio Call (`audio_call/`)

Encrypted P2P voice over UDP.

```
audio_call/
└── src/
    └── audio_call.c   # Opus encode/decode, PortAudio I/O, AES-GCM, HELLO
```

### 4. GUI (`gui/`)

Qt6 C++17 graphical application.

```
gui/
└── src/
    ├── main.cpp
    ├── mainwindow.cpp/h       # Main window, chat, connection dialogs
    ├── backend.cpp/h          # Network backend, crypto, ECDH, identity
    ├── audiocalldialog.cpp/h  # Audio call dialog
    ├── videocalldialog.cpp/h  # Video call dialog
    └── key_exchange.cpp       # Key exchange dialog
```

### 5. Key Exchange (`key-exchange/`)

Interactive ECDH key exchange utility.

```
key-exchange/
└── src/
    └── key-exchange.c   # Curve25519 keypair gen, encrypt/decrypt
```

### 6. Updater (`updater/`)

Auto-update manager.

```
updater/
└── src/
    └── updater.c   # Version check, download, update
```

---

## Protocol Specification

### TCP Message Frame

```
┌────────────┬────────┬────────────┬────────┬─────────────┬───────┬────────┬─────────┬──────────┐
│room_len(2) │room(N) │name_len(2) │name(N) │nonce_len(2) │nonce  │type(1) │clen(4)  │cipher(N) │
└────────────┴────────┴────────────┴────────┴─────────────┴───────┴────────┴─────────┴──────────┘
```

All integers are little-endian. Nonce is 12 bytes (AES-GCM). Cipher includes 16-byte auth tag.

### Message Types

```c
MSG_TYPE_TEXT          = 0   // Encrypted text message
MSG_TYPE_FILE_START   = 1   // File transfer metadata
MSG_TYPE_FILE_CHUNK   = 2   // File data chunk (8KB)
MSG_TYPE_FILE_END     = 3   // File transfer completion
MSG_TYPE_USER_LIST    = 4   // Room participant list (service, zero nonce)
MSG_TYPE_KEY_REQUEST  = 15  // ECDH key request (service, zero nonce)
MSG_TYPE_KEY_RESPONSE = 16  // ECDH key response (service, zero nonce)
MSG_TYPE_MEDIA_RELAY  = 17  // TCP media relay (raw encrypted media packet)
```

Service messages (types 4, 15, 16) use a zero nonce and are not encrypted with the room key.

### TCP Media Relay

When direct UDP is unavailable (NAT/VPN), audio and video calls can be relayed through the TCP server using MSG_TYPE_MEDIA_RELAY. Each call manager opens a dedicated TCP connection, registers with room+name, and media packets are wrapped in standard TCP frames. The server broadcasts media frames to other room participants.

### Server Features

- **TCP keepalive:** `SO_KEEPALIVE` with idle=60s, interval=10s, 3 probes — detects dead connections within ~90s
- **Duplicate name rejection:** Server sends "Name already taken" error message before disconnecting

### UDP Media Packets

**Audio:**
```
[0x01][sequence(8 BE)][AES-GCM(opus_frame) + 16-byte tag]
```

**Video:**
```
[0x02][sequence(8 BE)][AES-GCM(fragment_header + vp8_data) + 16-byte tag]
```

**HELLO handshake:**
```
[0x7F][nonce_prefix(4)][flags(1)][width(2 BE)][height(2 BE)][fps(1)]
```

### Key Derivation

Audio and video subkeys are derived from the master key via BLAKE2b KDF:
- Audio subkey: `crypto_kdf_derive_from_key(subkey, 32, id=1, ctx="fearaudi", master_key)`
- Video subkey: `crypto_kdf_derive_from_key(subkey, 32, id=2, ctx="fearvide", master_key)`

---

## ECDH Key Exchange Protocol

When `--create` is used, the client auto-generates a room key. When another client connects with `--join`:

1. **Joiner** sends `MSG_TYPE_KEY_REQUEST` containing their ephemeral X25519 public key
2. **Creator** receives the request, generates their own ephemeral X25519 keypair
3. **Creator** computes shared secret via `crypto_box`, encrypts the room key
4. **Creator** signs the response with their Ed25519 identity key
5. **Creator** sends `MSG_TYPE_KEY_RESPONSE` with encrypted key + signature + ephemeral pubkey
6. **Joiner** verifies the Ed25519 signature, decrypts the room key via `crypto_box_open`

Both clients now share the room key. The Ed25519 signature prevents MITM attacks.

---

## Identity Verification (TOFU)

Each client generates a persistent Ed25519 keypair (stored in `.fear/identity/`). On first connection to a peer, the public key is saved. On subsequent connections, the key is compared — a mismatch triggers a warning.

---

## Encryption Details

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM (AEAD) |
| Key size | 32 bytes (256 bits) |
| Nonce size | 12 bytes (96 bits) |
| Auth tag | 16 bytes (128 bits) |

Authenticated additional data (AAD) includes room name and user name (sent in plaintext as part of the frame header). The encrypted payload is message content, file data, or media frames.

---

## Constants

```c
#define MAX_ROOM          256    // Max room name length
#define MAX_NAME          256    // Max user name length
#define MAX_FILENAME      1024   // Max filename length
#define MAX_FRAME         65536  // Max message frame (64KB)
#define FILE_CHUNK_SIZE   8192   // File transfer chunk (8KB)
#define DEFAULT_PORT      8888   // Default server port
#define MAX_CLIENTS       100    // Max concurrent clients
#define CRYPTO_KEYBYTES   32     // AES-256-GCM key size
#define CRYPTO_NPUBBYTES  12     // AES-256-GCM nonce size
#define CRYPTO_ABYTES     16     // AES-256-GCM auth tag size
```

---

## Video Quality Presets

| Preset | Resolution | FPS | Bitrate |
|--------|-----------|-----|---------|
| LOW | 320x240 | 15 | 200 kbps |
| MEDIUM | 640x480 | 25 | 500 kbps |
| HIGH | 1280x720 | 30 | 1500 kbps |

Video frames are split into 1200-byte UDP fragments (max 128 per frame). Peer disconnect is detected after 5 seconds of silence.
