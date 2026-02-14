# F.E.A.R. - Fully Encrypted Anonymous Routing

<div align="center">

![F.E.A.R. Project](./doc/images/banner_small.png)

**Privacy-focused secure messaging platform with end-to-end encryption**

*Бояться - это нормально...*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue.svg)]()
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Language](https://img.shields.io/badge/Language-C11%20%7C%20C%2B%2B17-orange.svg)]()

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Technology Stack](#-technology-stack)
- [Security](#-security)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

## 🔍 Overview

**F.E.A.R. (Fully Encrypted Anonymous Routing)** is an open-source, cross-platform secure messaging system designed with privacy and security at its core. The project provides end-to-end encrypted communication channels with anonymous routing capabilities, ensuring maximum confidentiality for users.

### Key Principles

- **Privacy by Design**: Zero-knowledge architecture where even the server cannot access message content
- **Cryptographic Security**: Industry-standard encryption using libsodium (NaCl)
- **Transparency**: Open-source codebase available for audit and verification
- **Decentralization**: Self-hosted server support for complete infrastructure control

## ✨ Features

### Core Capabilities

- **🔐 End-to-End Encryption (E2EE)**
  - Messages encrypted on sender device, decrypted only by recipient
  - Server has zero access to plaintext content
  - Forward secrecy with ephemeral keys

- **🎭 Anonymous Routing**
  - IP address obfuscation
  - Metadata protection
  - Traffic analysis resistance

- **🎤 Encrypted Voice Calls**
  - Real-time audio streaming with Opus codec
  - Low-latency audio pipeline via PortAudio
  - End-to-end encrypted voice data

- **📹 Encrypted Video Calls**
  - Real-time VP8 video encoding/decoding via FFmpeg (libvpx)
  - Hardware-accelerated SDL3 YUV420P rendering
  - AES-256-GCM encryption per video fragment
  - Adaptive bitrate with quality presets (LOW/MEDIUM/HIGH)
  - UDP fragmentation for reliable frame delivery
  - Peer disconnect detection and automatic reconnect support
  - "No camera" receive-only mode

- **🔑 Secure Key Exchange**
  - Diffie-Hellman key exchange protocol
  - Safe room key distribution without pre-shared secrets
  - Interactive key exchange utility

- **🖥️ Multi-Interface Design**
  - Modern Qt6-based GUI application
  - Lightweight console client for servers/headless systems
  - Consistent functionality across interfaces

- **⬆️ Auto-Update System**
  - Built-in update manager with signature verification
  - Secure update delivery via HTTPS
  - Version compatibility checks

- **🌍 Cross-Platform**
  - Native support for Linux, Windows, macOS
  - Static linking for portable executables
  - Consistent behavior across platforms

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Client Layer                         │
│  ┌───────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐│
│  │  GUI App  │ │Console CLI │ │ Audio Call │ │ Video Call ││
│  │ (Qt6/C++) │ │   (C11)    │ │   (C11)    │ │   (C11)    ││
│  └───────────┘ └────────────┘ └────────────┘ └────────────┘│
└─────────────────────────────────────────────────────────┘
                           │
                           │ Encrypted Channel
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Server Layer                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  F.E.A.R. Server (Room Management, Routing)      │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Security Model

1. **Room-based Communication**: Users join encrypted rooms with shared keys
2. **Key Generation**: Cryptographically secure random key generation
3. **Key Distribution**: Diffie-Hellman protocol for secure key exchange
4. **Message Encryption**: Symmetric encryption with room keys (XSalsa20-Poly1305)
5. **Server Role**: Relay only - no access to keys or plaintext

## 🚀 Quick Start

### Prerequisites

#### Linux (Ubuntu/Debian)
```bash
# Install all dependencies at once:
./build.sh deps

# Or manually:
sudo apt-get update
sudo apt-get install build-essential cmake git pkg-config
sudo apt-get install qt6-base-dev libsodium-dev libcurl4-openssl-dev
sudo apt-get install libopus-dev portaudio19-dev
sudo apt-get install libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libavdevice-dev
sudo apt-get install libvpx-dev libsdl3-dev
```

> **Note:** SDL3 may not be available in your distro's repos yet. `./build.sh deps` will automatically build it from source if needed.


#### Windows
- **MinGW-w64** (GCC compiler)
- **CMake** 3.12+
- **Qt6** 6.2+
- External libraries (libsodium, curl, opus, portaudio) - see [BUILD.md](BUILD.md)

#### macOS
```bash
brew install cmake qt6 libsodium opus portaudio curl ffmpeg sdl3 libvpx
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/shchuchkin-pkims/fear.git
cd fear

# Build (Linux/macOS)
./build.sh

# Build (Windows)
build.bat
```

**Build output:**
- `build/fear_gui.exe` - GUI application
- `build/bin/` - Command-line utilities

For detailed build instructions, see [BUILD.md](BUILD.md).

### Quick Usage Example

```bash
# 1. Generate room key (automatically copied to clipboard in GUI)
cd build/bin
./fear genkey
# Output to stdout: z6aK3_k9I7rmpy6Sn-84QZ9Yc0p3T7VhzReWCKE0x4I
# SECURITY: Key is NOT saved to disk by default

# 2. Start server (on trusted machine)
./fear server --port 7777

# 3. User A: Connect to room (key passed via stdin for security)
echo "YOUR_KEY" | ./fear client --host SERVER_IP --port 7777 \
    --room myroom --name Alice

# OR use --key-file (recommended for scripts)
./fear client --host SERVER_IP --port 7777 \
    --room myroom --key-file room_key.txt --name Alice

# 4. User B: Join same room
echo "YOUR_KEY" | ./fear client --host SERVER_IP --port 7777 \
    --room myroom --name Bob
```

**Security Notes:**
- Keys are **never saved to disk automatically** - they're output to stdout/clipboard only
- When using CLI, pass keys via **stdin** or **--key-file** (not command-line args)
- Command-line args are visible in process lists - avoid `--key` parameter
- GUI automatically copies generated keys to clipboard

## 📦 Installation

### Binary Releases

Pre-built binaries are available on the [Releases](https://github.com/shchuchkin-pkims/fear/releases) page.

### Building from Source

Detailed compilation instructions for all platforms are in [BUILD.md](BUILD.md).

## 📘 Usage

### GUI Application

Launch the graphical interface:

```bash
cd build
./fear_gui        # Linux/macOS
fear_gui.exe      # Windows
```

### Console Client

#### Generate Room Key

```bash
cd build/bin
./fear genkey
```

Example output:
```
z6aK3_k9I7rmpy6Sn-84QZ9Yc0p3T7VhzReWCKE0x4I
Room key generated successfully.
IMPORTANT: Copy the key above to clipboard and share it securely.
           The key is NOT saved to disk for security reasons.
```

**Security Features (v0.3+):**
- ✅ Keys output to **stdout** (not saved to files automatically)
- ✅ GUI version **auto-copies to clipboard** for convenience
- ✅ No sensitive data left in terminal scrollback (stderr messages only)
- ✅ User can redirect to file if needed: `./fear genkey > my_key.txt`

⚠️ **Important**: Share this key securely with intended participants only.

#### Start Server

```bash
./fear server --port 7777
```

**Security Note**: Only run servers on trusted infrastructure. Never connect to unknown third-party servers.

#### Connect as Client

**Recommended (secure key input via stdin):**
```bash
echo "z6aK3_k9I7rmpy6Sn-84QZ9Yc0p3T7VhzReWCKE0x4I" | ./fear client \
    --host 127.0.0.1 \
    --port 7777 \
    --room myroom \
    --name YourName
```

**Alternative (using key file):**
```bash
./fear client \
    --host 127.0.0.1 \
    --port 7777 \
    --room myroom \
    --key-file room_key.txt \
    --name YourName
```

**⚠️ Deprecated (insecure - key visible in process list):**
```bash
# DO NOT USE in production - for testing only
./fear client --host 127.0.0.1 --port 7777 \
    --room myroom --key YOUR_KEY --name YourName
```

### Secure Key Exchange

For secure room key distribution without a pre-shared secret:

```bash
cd build/bin
./key-exchange
```

The utility implements Diffie-Hellman key exchange:

1. **User A**: Select "Send key" → generates p, g, public_key_A
2. **User A** → **User B**: Share p, g, public_key_A (can be public)
3. **User B**: Input p, g, public_key_A → generates public_key_B
4. **User B** → **User A**: Share public_key_B
5. **User A**: Input public_key_B + room_key → generates encrypted_key
6. **User A** → **User B**: Share encrypted_key
7. **User B**: Input encrypted_key → decrypts room_key

Both users now have the same room key without ever transmitting it in plaintext.

### Audio Calls

Encrypted voice communication:

```bash
cd build/bin

# Generate audio call key (outputs to stdout, auto-copied in GUI)
./audio_call genkey
# Output: b1aae1360b0e242c18bad535b1179133789c60d8fc3063a259f25b7bcab9a938

# List available audio devices
./audio_call listdevices

# Start call (key via stdin for security)
echo "YOUR_KEY" | ./audio_call call 192.168.1.100 50000

# Or listen for incoming call
echo "YOUR_KEY" | ./audio_call listen 50000
```

**Features:**
- ✅ Opus codec for high-quality, low-latency audio
- ✅ Real-time AES-256-GCM encryption with libsodium
- ✅ PortAudio for cross-platform audio I/O
- ✅ Secure key input via stdin (v0.3+)
- ✅ Audio device selection with Host API info (fixes duplicate names)

### Video Calls

Encrypted video communication:

```bash
cd build/bin

# Generate video call key (outputs to stdout, auto-copied in GUI)
./video_call genkey
# Output: a3f1c2e4b5d6...

# List available cameras and audio devices
./video_call listdevices

# Start call (key via stdin for security)
echo "YOUR_KEY" | ./video_call call 192.168.1.100 50000

# Or listen for incoming call
echo "YOUR_KEY" | ./video_call listen 50000

# Options
echo "YOUR_KEY" | ./video_call call 192.168.1.100 50000 \
    --quality high \
    --camera "/dev/video0" \
    --no-audio
```

**Features:**
- ✅ VP8 video codec via FFmpeg (libvpx)
- ✅ Hardware-accelerated SDL3 display (YUV420P)
- ✅ AES-256-GCM encryption per fragment with libsodium
- ✅ Adaptive bitrate control (LOW/MEDIUM/HIGH presets)
- ✅ Peer disconnect detection with automatic reconnect
- ✅ "No camera" receive-only mode
- ✅ GUI integration with camera selection

### Auto-Updater

The update manager checks for new versions:

```bash
cd build/bin
./updater
```

Configuration: `updater.conf`

## 📁 Project Structure

### Source Code

```
fear-main/
├── client-console/       # Console client/server (C11)
│   └── src/
│       ├── main.c        # Entry point
│       ├── server.c      # Server implementation
│       ├── client.c      # Client implementation
│       └── common.c      # Shared utilities
├── gui/                  # Qt6 GUI application (C++17)
│   └── src/
│       ├── main.cpp
│       └── key_exchange.cpp
├── audio_call/           # Voice call utility (C11)
│   └── src/
│       └── audio_call.c
├── video_call/           # Video call utility (C11)
│   ├── include/          # Headers (video_types.h, etc.)
│   └── src/
│       ├── video_call.c      # Main orchestration, threads, encryption
│       ├── video_capture.c   # FFmpeg camera capture (dshow/V4L2)
│       ├── video_codec.c     # VP8 encode/decode
│       ├── video_display.c   # SDL3 YUV420P rendering
│       ├── video_fragment.c  # UDP fragmentation/reassembly
│       └── video_quality.c   # Adaptive bitrate control
├── key-exchange/         # Key exchange tool (C11)
│   └── src/
│       └── key-exchange.c
├── updater/              # Update manager (C11)
│   └── src/
│       └── updater.c
├── lib/                  # External libraries (Windows)
├── doc/                  # Documentation
│   ├── images/
│   └── manual.pdf
├── CMakeLists.txt        # Main CMake configuration
├── build.sh              # Linux/macOS build script
├── build.bat             # Windows build script
├── BUILD.md              # Build documentation
├── QUICKSTART.md         # Quick start guide
└── README.md             # This file
```

### Build Output

```
build/
├── fear_gui.exe          # GUI application
├── *.dll                 # Qt dependencies (Windows)
├── platforms/            # Qt platform plugins
├── bin/                  # Console utilities
│   ├── fear.exe          # Client/server
│   ├── audio_call.exe    # Voice calls
│   ├── video_call.exe    # Video calls
│   ├── key-exchange.exe  # Key exchange
│   ├── updater.exe       # Update manager
│   ├── cacert.pem        # CA certificates
│   ├── libcurl-x64.dll   # libcurl (Windows)
│   └── updater.conf      # Updater configuration
└── doc/
    └── manual.pdf        # User manual
```

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Core Language** | C11, C++17 | Performance, memory safety |
| **GUI Framework** | Qt 6.2+ | Cross-platform UI |
| **Build System** | CMake 3.12+ | Multi-platform builds |
| **Cryptography** | libsodium (NaCl) | Encryption, signatures, key derivation |
| **Audio Codec** | Opus | High-quality, low-latency voice |
| **Audio I/O** | PortAudio | Cross-platform audio interface |
| **Video Codec** | VP8 (libvpx via FFmpeg) | Real-time video encoding/decoding |
| **Video Capture** | FFmpeg (libavdevice) | Camera capture (dshow/V4L2) |
| **Video Display** | SDL3 | Hardware-accelerated YUV rendering |
| **HTTP Client** | libcurl | Secure update downloads |
| **Networking** | POSIX sockets, Winsock2 | Client-server communication |

### Cryptographic Primitives

- **Symmetric Encryption**: XSalsa20-Poly1305 (authenticated encryption)
- **Key Exchange**: X25519 (Elliptic-Curve Diffie-Hellman)
- **Key Derivation**: Argon2id (memory-hard KDF)
- **Random Generation**: libsodium's CSPRNG

## 🔒 Security

### Threat Model

**Protected Against:**
- Network eavesdropping (encryption in transit)
- Server compromise (E2EE, zero-knowledge)
- Message tampering (authenticated encryption)
- Man-in-the-middle (when using key exchange properly)

**Not Protected Against:**
- Endpoint compromise (malware on user device)
- Social engineering (key sharing with adversaries)
- Traffic analysis (metadata leakage)
- Malicious server operators (room metadata visible)

### Security Best Practices

1. **Server Trust**: Only connect to servers you control or explicitly trust
2. **Key Distribution**: Use the key-exchange utility for initial setup
3. **Key Storage**:
   - ✅ **v0.3+**: Keys output to stdout/clipboard only (not auto-saved to disk)
   - ⚠️ Avoid saving keys in plaintext files when possible
   - 🔒 Use encrypted key stores or system keychains for long-term storage
4. **Key Input Security**:
   - ✅ **Recommended**: Pass keys via stdin or --key-file
   - ⚠️ **Avoid**: Command-line `--key` argument (visible in process lists)
5. **Updates**: Keep software up-to-date with security patches
6. **Verification**: Audit the open-source code before deployment
7. **Audio Device Privacy**: GUI shows Host API with device names to prevent confusion

### Responsible Disclosure

Security vulnerabilities should be reported privately to the maintainers. Please do not create public issues for security bugs.

## 🗺️ Roadmap

### ✅ Completed (v0.4.0)

- [x] E2E encrypted messaging (console)
- [x] Client-server architecture
- [x] Qt6 GUI application
- [x] Diffie-Hellman key exchange utility
- [x] Encrypted voice calls (Opus + libsodium)
- [x] Auto-update system
- [x] Cross-platform build system
- [x] Static linking (Windows portable builds)
- [x] File transfer with encryption
- [x] **Secure key handling** (v0.3+):
  - [x] Keys output to stdout (not auto-saved to files)
  - [x] GUI auto-copy to clipboard
  - [x] Secure key input via stdin/--key-file
  - [x] Deprecation warnings for insecure --key argument
- [x] **Audio device improvements** (v0.3+):
  - [x] Host API info in device names (fixes duplicates)
- [x] **Encrypted video calls** (v0.4+):
  - [x] VP8 video codec with FFmpeg/libvpx
  - [x] SDL3 hardware-accelerated display
  - [x] AES-256-GCM per-fragment encryption
  - [x] Adaptive bitrate (LOW/MEDIUM/HIGH)
  - [x] Peer disconnect detection and reconnect
  - [x] "No camera" receive-only mode
  - [x] GUI integration with camera selection

### 🚧 In Progress

- [ ] GUI improvements and UX refinement
- [ ] Mobile applications (Android)

### 📋 Planned

- [ ] Push notification service
- [ ] Custom UI themes
- [ ] Multiple encryption protocol support
- [ ] Dynamic key changing

### 🔮 Future Vision

- [ ] Web-based client (WebAssembly)
- [ ] Mobile applications (iOS)
- [ ] Hardware security token support


## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Ways to Contribute

- **Code**: Implement new features, fix bugs, improve performance
- **Documentation**: Enhance guides, tutorials, API documentation
- **Testing**: Report bugs, test on different platforms
- **Security**: Audit code, report vulnerabilities responsibly

### Development Workflow

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/your-username/fear.git`
3. **Create** a feature branch: `git checkout -b feature/amazing-feature`
4. **Make** your changes following code style guidelines
5. **Test** thoroughly on your target platform(s)
6. **Commit** with clear messages: `git commit -m "Add amazing feature"`
7. **Push** to your fork: `git push origin feature/amazing-feature`
8. **Open** a Pull Request with detailed description

### Code Style

- **C code**: Follow Linux kernel style guidelines
- **C++ code**: Follow Qt coding conventions
- **Comments**: Document complex logic and security-critical sections
- **Testing**: Add tests for new functionality

### Communication

- **Issues**: Report bugs and feature requests on GitHub Issues
- **Discussions**: Join project discussions in the Discussions tab
- **Pull Requests**: Reference related issues in PR descriptions

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 F.E.A.R. Project Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

## 📞 Support

- **Documentation**: [BUILD.md](BUILD.md), [QUICKSTART.md](QUICKSTART.md)
- **Issues**: [GitHub Issues](https://github.com/shchuchkin-pkims/fear/issues)
- **Discussions**: [GitHub Discussions](https://github.com/shchuchkin-pkims/fear/discussions)

## 🙏 Acknowledgments

- **libsodium**: Daniel J. Bernstein and contributors
- **Opus Audio Codec**: Xiph.Org Foundation
- **PortAudio**: PortAudio community
- All open-source contributors and security researchers

---

<div align="center">

**Stay Anonymous. Stay Secure.**

Made by Shchuchkin E. Yu. and the F.E.A.R. Project community

[⬆ Back to Top](#fear---fully-encrypted-anonymous-routing)

</div>
