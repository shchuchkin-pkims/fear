# F.E.A.R. - Fully Encrypted Anonymous Routing

<div align="center">

![F.E.A.R. Project](./doc/images/banner_small.png)

**Privacy-focused secure messaging platform with end-to-end encryption**

*Бояться - это нормально...*

[![Server: AGPL v3](https://img.shields.io/badge/Server-AGPL%20v3-blue.svg)](LICENSE)
[![Clients: GPL v3](https://img.shields.io/badge/Clients-GPL%20v3-blue.svg)](LICENSE.GPL-3.0)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Android-blue.svg)]()
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Language](https://img.shields.io/badge/Language-C11%20%7C%20C%2B%2B17-orange.svg)]()

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Mobile App](#mobile-app)

</div>

---

## Overview

**F.E.A.R. (Fully Encrypted Anonymous Routing)** is an open-source, cross-platform secure messaging system with end-to-end encrypted text, voice, and video communication. The server operates in zero-knowledge mode — it relays encrypted data without access to keys or plaintext.

Available as a desktop application (Linux/Windows) with GUI and CLI, and as a [mobile app for Android](https://github.com/shchuchkin-pkims/fear-mobile).

## Features

- **End-to-end encrypted messaging** — AES-256-GCM with libsodium; server never sees plaintext
- **Encrypted voice calls** — Opus codec, AES-256-GCM over UDP, low-latency P2P
- **Encrypted video calls** — VP8 (libvpx), AES-256-GCM per fragment, SDL3 hardware-accelerated display, adaptive bitrate (LOW/MEDIUM/HIGH)
- **ECDH key exchange** — Create rooms with auto-generated keys or join via X25519 exchange; no pre-shared secrets needed
- **Identity verification** — Ed25519 keypairs with Trust On First Use (TOFU) model
- **File transfer** — Encrypted file sharing with CRC32 integrity verification
- **GUI and CLI** — Qt6 graphical interface and lightweight console client/server
- **Auto-updater** — Built-in update manager with version checks
- **Cross-platform** — Linux and Windows with static linking support

## Quick Start

### Prerequisites

**Linux (Ubuntu/Debian):**
```bash
./build.sh deps
```

**Windows:**
- MinGW-w64, CMake 3.12+, Qt6 6.2+
- External libraries in `lib/` directory — see [Build Instructions](doc/BUILD.md)

### Build

```bash
# Linux
./build.sh

# Windows
build.bat
```

### Usage

**GUI (recommended):**
```bash
cd build && ./fear_gui
```

The GUI provides three connection modes:
- **Create Room** — auto-generates an encryption key and starts a new room
- **Join Room** — performs ECDH key exchange with the room creator
- **Connect** — connects with a known key (manual entry)

**Console — Create a room:**
```bash
cd build/bin
./fear server --port 7777
./fear client --host IP --port 7777 \
    --room myroom --name Alice --create
```

**Console — Join a room (ECDH):**
```bash
./fear client --host IP --port 7777 \
    --room myroom --name Bob --join
```

**Console — Connect with known key:**
```bash
echo "KEY" | ./fear client --host IP --port 7777 \
    --room myroom --name Charlie
```

For detailed usage see [Quick Start Guide](doc/QUICKSTART.md) and [User Manual](doc/manual.md).

## Architecture

```
[Client A] <——encrypted——> [Server] <——encrypted——> [Client B]
                              |
                    (zero-knowledge relay)
```

### Protocol

| Channel | Format |
|---------|--------|
| TCP chat | `[2 room_len][room][2 name_len][name][2 nonce_len][nonce][1 type][4 clen][cipher]` (LE) |
| UDP audio | `[0x01][seq(8 BE)][AES-GCM(opus) + 16-byte tag]` |
| UDP video | `[0x02][seq(8 BE)][AES-GCM(vp8_fragment) + 16-byte tag]` |
| HELLO | `[0x7F][prefix(4)][flags(1)][width(2 BE)][height(2 BE)][fps(1)]` |

### Cryptography

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Symmetric encryption | AES-256-GCM | Messages, audio, video |
| Key exchange | X25519 + XSalsa20-Poly1305 | ECDH room key transport |
| Identity | Ed25519 | Peer authentication (TOFU) |
| Key derivation | BLAKE2b | Audio/video subkeys from master key |
| Integrity | CRC32 | File transfer verification |

### Security Model

**Server is zero-knowledge:**
- Cannot read messages (encrypted with room key)
- Cannot decrypt media (derived keys never leave clients)
- Cannot forge identities (Ed25519 signed)

**ECDH key exchange flow:**
1. Room creator generates a key and starts the room (`--create`)
2. Joiner connects and initiates ECDH exchange (`--join`)
3. Ephemeral X25519 keypairs are exchanged; responder signs with Ed25519
4. Room key is transported via `crypto_box` (X25519 + XSalsa20-Poly1305)
5. Both parties derive the same room key without pre-shared secrets

### Data Storage

Where your data lives - the server knows as little as possible:

| Data | Where | Details |
|------|-------|---------|
| Message history | **Client only** | Desktop: SQLite, Android: Room. 10 MB FIFO per chat, "Clear history" button in every chat |
| Contact list | Client + server (encrypted blob) | Encrypted locally with a key derived from your identity key (HKDF). The server stores only ciphertext, its size and update time |
| Identity keys | **Client only** | Desktop: `~/.fear/identity`, file permissions 0600 (OS keychain / DPAPI integration planned). Android: Keystore-backed EncryptedFile |
| Identity backup | Manual, user-initiated | Encrypted `.fbk` file (Argon2id + AES-256-GCM) or QR code. No server-side backup by design |
| Room keys, trusted peers (TOFU) | **Client only** | Never sent to the server |
| Server database | Server (SQLite in a Docker volume) | Handles (`@username` - public key), encrypted user blobs, room routing state. No plaintext, ever |

Notes:

- The server does **not** store message content: messages are relayed to currently online participants only. Offline delivery (an encrypted server-side inbox, deleted after ACK) is planned for a later phase - see the [roadmap](doc/TODO.md).
- New room members cannot read messages sent before they joined (Signal-style model). If needed, history can be shared explicitly via export/import.
- Losing your device without a backup means losing your identity and history - export an encrypted backup from Settings.

## Project Structure

```
fear-main/
├── client-console/     # Console client/server (C11)
├── gui/                # Qt6 GUI application (C++17)
├── audio_call/         # Encrypted voice calls (C11)
├── video_call/         # Encrypted video calls (C11)
├── key-exchange/       # Key exchange utility (C11)
├── updater/            # Auto-update manager (C11)
├── lib/                # External libraries (Windows)
├── doc/                # Documentation
├── build.sh            # Linux build script
├── build.bat           # Windows build script
└── CMakeLists.txt      # CMake configuration
```

**Build output:**
```
build/
├── fear_gui            # GUI application
└── bin/
    ├── fear            # Console client/server
    ├── audio_call      # Voice call utility
    ├── video_call      # Video call utility
    ├── key-exchange    # Key exchange utility
    └── updater         # Update manager
```

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Core language | C11, C++17 | Performance and portability |
| GUI | Qt 6.2+ | Cross-platform desktop UI |
| Build system | CMake 3.12+ | Multi-platform builds |
| Cryptography | libsodium | AES-GCM, Ed25519, X25519, BLAKE2b |
| Audio codec | Opus + PortAudio | High-quality low-latency voice |
| Video codec | VP8 (libvpx via FFmpeg) | Real-time video encoding |
| Video capture | FFmpeg (libavdevice) | Camera capture (dshow/V4L2) |
| Video display | SDL3 | Hardware-accelerated YUV rendering |
| HTTP client | libcurl | Update downloads |

## Security

### Threat Model

**Protected against:**
- Network eavesdropping (end-to-end encryption)
- Server compromise (zero-knowledge architecture)
- Message tampering (authenticated encryption)
- MITM on key exchange (Ed25519 signed ECDH)

**Not protected against:**
- Endpoint compromise (malware on user device)
- Traffic analysis (metadata visible to server/network)

### Best Practices

- Use `--create` / `--join` for automatic key exchange instead of manual key sharing
- Pass keys via stdin or `--key-file`, never as CLI arguments (visible in process lists)
- Run your own server for full infrastructure control
- Verify peer identity fingerprints on first connection

## Documentation

- [Quick Start Guide](doc/QUICKSTART.md)
- [Build Instructions](doc/BUILD.md)
- [Code Structure](doc/CODE_STRUCTURE.md)
- [User Manual](doc/manual.md)
- [Roadmap](doc/TODO.md)
- [Security Audit](doc/SECURITY_AUDIT_2026-07.md)

## Mobile App

An Android client is available at **[fear-mobile](https://github.com/shchuchkin-pkims/fear-mobile)**.

Fully compatible with the desktop server — supports encrypted text, audio calls, video calls, ECDH key exchange, identity verification, file transfer, light/dark themes, and push notifications.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/name`
3. Make changes and test on your target platform(s)
4. Open a Pull Request with a description of your changes

Report bugs and security vulnerabilities via [GitHub Issues](https://github.com/shchuchkin-pkims/fear/issues). Security issues should be reported privately.

## License

F.E.A.R. is free software.

- **Server** (`client-console/`, `identity/`, `Dockerfile`, `web/server.js`) - **GNU AGPL-3.0-or-later**, see [LICENSE](LICENSE).
- **Clients** (`gui/`, `audio_call/`, `video_call/`, `key-exchange/`, `updater/`, `web/public/`) - **GNU GPL-3.0-or-later**, see [LICENSE.GPL-3.0](LICENSE.GPL-3.0).

The AGPL applies to the server because it is offered over a network: section 13 requires operators of a modified server to publish their changes, so users can verify that the server they connect to matches the published source.

Full component-by-component mapping: [LICENSING.md](LICENSING.md).

## Acknowledgments

- **[libsodium](https://doc.libsodium.org/)** — Daniel J. Bernstein and contributors
- **[Opus](https://opus-codec.org/)** — Xiph.Org Foundation
- **[PortAudio](http://www.portaudio.com/)** — PortAudio community
- **[FFmpeg](https://ffmpeg.org/)** — FFmpeg developers
- **[SDL3](https://www.libsdl.org/)** — SDL contributors
- **[libvpx](https://www.webmproject.org/)** — WebM Project

---

<div align="center">

**Stay Anonymous. Stay Secure.**

Made by Shchuchkin E. Yu. and the F.E.A.R. Project community

[Back to Top](#fear---fully-encrypted-anonymous-routing)

</div>
