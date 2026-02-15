# Quick Start Guide

Get started with F.E.A.R. in minutes.

## Build

**Linux:**
```bash
./build.sh deps    # install dependencies (first time only)
./build.sh         # build everything
```

**Windows:**
```batch
build.bat
```

## What You Get

```
build/
├── fear_gui          # GUI application
└── bin/
    ├── fear          # Console client/server
    ├── audio_call    # Voice call utility
    ├── video_call    # Video call utility
    ├── key-exchange  # Key exchange utility
    └── updater       # Update manager
```

## GUI Application (Recommended)

```bash
cd build && ./fear_gui
```

The GUI provides three connection modes:

### Create Room
1. Menu > Connection > Create Room
2. Enter server host, port, room name, and your name
3. Click **Create** — a key is auto-generated and copied to clipboard
4. Share the key securely with participants

### Join Room (ECDH)
1. Menu > Connection > Join Room
2. Enter server host, port, room name, and your name
3. Click **Join** — ECDH key exchange happens automatically
4. No pre-shared key needed; the room creator's client sends the key securely

### Connect (Manual Key)
1. Menu > Connection > Connect
2. Enter all fields including the room key
3. Click **Connect**

### Other GUI Features
- Audio calls: Menu > Audio call > Start audio call
- Video calls: Menu > Video call > Start video call
- File transfer: Click "Send file" button in chat
- Key exchange: Menu > Keys > Key exchange
- Identity: Trusted keys are managed automatically (TOFU)

## Console Client

### Create a Room

```bash
cd build/bin

# Start server
./fear server --port 7777

# Create room (auto-generate key)
./fear client --host 127.0.0.1 --port 7777 \
    --room myroom --name Alice --create
```

The generated key is printed to stdout. Share it securely.

### Join a Room (ECDH)

```bash
./fear client --host SERVER_IP --port 7777 \
    --room myroom --name Bob --join
```

The ECDH exchange happens automatically — no key needed.

### Connect with Known Key

```bash
# Key via stdin (recommended)
echo "YOUR_KEY" | ./fear client --host SERVER_IP --port 7777 \
    --room myroom --name Charlie

# Key from file
./fear client --host SERVER_IP --port 7777 \
    --room myroom --name Charlie --key-file room_key.txt
```

### Audio Calls

```bash
# Generate key
./audio_call genkey

# Listen for call
echo "KEY" | ./audio_call listen 50000

# Make a call
echo "KEY" | ./audio_call call REMOTE_IP 50000
```

### Video Calls

```bash
# Generate key
./video_call genkey

# Listen for call
echo "KEY" | ./video_call listen 50000

# Make a call
echo "KEY" | ./video_call call REMOTE_IP 50000

# Options
echo "KEY" | ./video_call call REMOTE_IP 50000 --quality high
echo "KEY" | ./video_call listen 50000 --no-camera
```

## Build Commands

| Task | Linux | Windows |
|------|-------|---------|
| Build | `./build.sh` | `build.bat` |
| Clean | `./build.sh clean` | `build.bat clean` |
| Rebuild | `./build.sh rebuild` | `build.bat rebuild` |
| Install deps | `./build.sh deps` | N/A |

## Security Tips

- Use `--create` / `--join` for key exchange — avoids manual key sharing
- Pass keys via stdin or `--key-file`, not CLI arguments (visible in process lists)
- Verify peer identity on first connection (TOFU model)
- Only connect to servers you trust

## Need Help?

- Full build instructions: [BUILD.md](BUILD.md)
- Code structure: [CODE_STRUCTURE.md](CODE_STRUCTURE.md)
- User manual: [manual.md](manual.md)
- Project README: [README.md](../README.md)
