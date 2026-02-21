# Roadmap

## Release History

| Version | Highlights | Status |
|---------|-----------|--------|
| **v0.1** | Basic messaging, key exchange, GUI | Done |
| **v0.2** | Encrypted audio calls (Opus + AES-GCM) | Done |
| **v0.3** | Secure key handling, file transfer, auto-updater, mobile app | Done |
| **v0.4** | Encrypted video calls (VP8 + SDL3 + AES-GCM) | Done |
| **v0.4.1** | ECDH key exchange, Ed25519 identity (TOFU), Android v0.4.1 | Done |
| **v0.4.2** | TCP media relay, server keepalive, Android in-app updates | Done |
| **v1.0** | CI/CD, security hardening, full testing | Planned |

---

## Completed

### v0.4.2 — TCP Media Relay & Server Hardening
- [x] TCP media relay for audio/video calls through server (MSG_TYPE_MEDIA_RELAY = 17)
- [x] TCP keepalive on server (idle=60s, interval=10s, 3 probes — dead connection detection in ~90s)
- [x] Duplicate name rejection with error message to client
- [x] Android: in-app update (check GitHub releases, download and install APK)
- [x] Android: menu button on connection screen (theme, trusted keys, updates)
- [x] Android: online users list persists across theme changes
- [x] Android: close previous connection before starting new one (fixes ghost session bug)

### v0.4.1 — ECDH & Identity
- [x] ECDH key exchange (X25519 + crypto_box) — `--create` / `--join` modes
- [x] Ed25519 identity verification with TOFU model
- [x] GUI: Create Room / Join Room / Connect buttons
- [x] Android app updated to v0.4.1 (ECDH, identity, video calls, themes, push notifications)

### v0.4.0 — Video Calls
- [x] VP8 video codec via FFmpeg (libvpx)
- [x] SDL3 hardware-accelerated YUV420P display
- [x] AES-256-GCM encryption per fragment
- [x] UDP fragmentation/reassembly (1200B chunks, up to 128 per frame)
- [x] Adaptive bitrate (LOW/MEDIUM/HIGH presets)
- [x] Peer disconnect detection (5s timeout) + auto reconnect
- [x] "No camera" receive-only mode
- [x] GUI integration with camera/quality selection

### v0.3.0 — Security & Features
- [x] AES-256-GCM encryption (upgraded from XSalsa20)
- [x] Secure key generation (stdout only, not saved to disk)
- [x] GUI auto-copy keys to clipboard
- [x] Secure key input via stdin / `--key-file` (deprecate `--key` argument)
- [x] File transfer with CRC32 integrity verification
- [x] Auto-updater
- [x] Audio device Host API in names (fixes duplicates)
- [x] Android mobile app (initial release)

### v0.2.0 — Audio Calls
- [x] Encrypted voice calls (Opus + PortAudio + AES-GCM over UDP)

### v0.1.0 — Foundation
- [x] Client-server architecture with room-based chat
- [x] E2E encrypted messaging
- [x] Qt6 GUI application
- [x] Console client/server
- [x] Diffie-Hellman key exchange utility

---

## In Progress

- [ ] Documentation updates and localization
- [ ] Security audit remediation (see SECURITY_AUDIT.md)

## Planned

### Security
- [ ] Secure key storage on client (system keychain integration)
- [ ] Automatic key rotation (rekeying)
- [ ] Binary signature verification

### Networking
- [ ] NAT traversal (ICE/STUN/TURN)
- [ ] TLS for TCP transport layer

### Quality
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Unit tests for cryptographic functions
- [ ] Load testing for server and calls

### Features
- [ ] Noise suppression and auto-level for audio
- [ ] iOS mobile app

---

## Changelog

### v0.4.2

**TCP Media Relay:**
- MSG_TYPE_MEDIA_RELAY (17) — audio/video calls relayed through TCP server when UDP is blocked
- Each call manager opens dedicated TCP connection, registers with room+name
- Server broadcasts media frames to room participants

**Server Hardening:**
- TCP keepalive (SO_KEEPALIVE, idle=60s, interval=10s, 3 probes) — detects dead connections in ~90s
- Duplicate name rejection sends error message before disconnecting

**Android v0.4.2:**
- In-app update: check GitHub releases, download and install APK directly
- Menu button on connection screen
- Online users list preserved on theme change
- Previous connection closed before starting new one (fixes ghost session)

### v0.4.1

**ECDH Key Exchange:**
- MSG_TYPE_KEY_REQUEST (15) / MSG_TYPE_KEY_RESPONSE (16) service messages
- X25519 ephemeral keypairs + crypto_box for key transport
- Ed25519 signature on ECDH response prevents MITM
- CLI: `--create` (auto-gen key), `--join` (ECDH exchange)
- GUI: Create Room / Join Room / Connect buttons

**Identity Verification:**
- Ed25519 keypair generation and persistent storage (`.fear/identity/`)
- Trust On First Use (TOFU) — first-seen pubkey is saved, mismatch = warning
- Peer verification during calls (guarded against spam)

**Android v0.4.1:**
- ECDH key exchange (Create Room / Join Room)
- Identity verification
- Video calls
- Light/dark theme toggle
- Push notifications for background messages
- Recent hosts dropdown

### v0.4.0

**Video Calls:**
- VP8 video codec via FFmpeg (libvpx), SDL3 YUV420P display
- AES-256-GCM per-fragment encryption, UDP fragmentation
- Adaptive bitrate (LOW: 320x240@15fps, MEDIUM: 640x480@25fps, HIGH: 1280x720@30fps)
- Peer disconnect detection (5s timeout), auto reconnect
- "No camera" receive-only mode, GUI camera/quality selection

### v0.3.0

**Security:**
- Keys output to stdout only (not auto-saved to disk)
- GUI auto-copies keys to clipboard
- Secure key input via stdin / `--key-file`
- `--key` CLI argument deprecated (visible in process lists)

**Audio:**
- Host API info in device names (e.g., "Microphone (WASAPI)")
- Fixes duplicate device names across APIs

**Other:**
- File transfer with encryption and CRC32 verification
- Auto-updater with version checks
