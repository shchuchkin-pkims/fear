# Quick Start Guide

Get started with F.E.A.R. in minutes!

## Build the Project

### One Command Build

**Linux/macOS:**
```bash
./build.sh
```

**Windows:**
```batch
build.bat
```

## What You Get

After build completes:

```
build/
├── fear_gui.exe      ← Main GUI application (with Qt files)
├── *.dll, platforms/ ← Qt dependencies
├── bin/              ← Console utilities
│   ├── fear.exe      ← Console client-server
│   ├── audio_call.exe← Audio calling tool
│   ├── video_call.exe← Video calling tool
│   ├── key-exchange  ← Key exchange utility
│   └── updater.exe   ← Update manager
└── doc/
    └── manual.pdf    ← User manual
```

## Run the Application

### GUI Application (Recommended for beginners)

**Start the GUI:**
```bash
cd build
./fear_gui          # Linux/macOS
fear_gui.exe        # Windows
```

**Features:**
- ✅ Generate keys with automatic clipboard copy
- ✅ Visual room management
- ✅ Audio call interface with device selection
- ✅ File transfer support
- ✅ No command-line knowledge required

### Console Client (Advanced users)

**Basic Commands:**
```bash
cd build/bin

# Generate room key (outputs to stdout)
./fear genkey

# Start server
./fear server --port 7777

# Join room (key via stdin - secure)
echo "YOUR_KEY" | ./fear client --host IP --port 7777 --room myroom --name Alice
```

### Audio Calls

**Console:**
```bash
cd build/bin

# Generate audio key
./audio_call genkey

# List audio devices (v0.3+: shows Host API to avoid duplicates)
./audio_call listdevices

# Start call (key via stdin)
echo "YOUR_KEY" | ./audio_call call IP PORT
```

**GUI:**
- Open "Audio call" menu → "Start audio call"
- Generate key (auto-copied to clipboard)
- Select input/output devices
- Share key with participant securely

### Video Calls

**Console:**
```bash
cd build/bin

# Generate video call key
./video_call genkey

# List cameras and audio devices
./video_call listdevices

# Start call (key via stdin)
echo "YOUR_KEY" | ./video_call call IP PORT

# Listen for incoming call
echo "YOUR_KEY" | ./video_call listen PORT

# Options: quality, camera, no-camera mode
echo "YOUR_KEY" | ./video_call call IP PORT --quality high --camera "/dev/video0"
echo "YOUR_KEY" | ./video_call listen PORT --no-camera
```

**GUI:**
- Open "Video call" menu → "Start video call"
- Generate key (auto-copied to clipboard)
- Select camera (or "No camera" for receive-only)
- Choose quality preset (LOW/MEDIUM/HIGH)
- Share key with participant securely

## Other Commands

**Clean temporary files:**
```bash
./build.sh clean     # Linux/macOS
build.bat clean      # Windows
```

**Rebuild everything:**
```bash
./build.sh rebuild   # Linux/macOS
build.bat rebuild    # Windows
```

## Security Tips 🔒

**Security Improvements (v0.3.0+):**

1. **Key Generation:**
   - ✅ Keys are **NOT auto-saved to disk** (output to stdout/clipboard only)
   - ✅ GUI automatically copies keys to clipboard
   - ⚠️ Save keys securely if needed (encrypted storage recommended)

2. **Key Input (CLI):**
   - ✅ **Recommended**: `echo "KEY" | ./fear client ...` (stdin)
   - ✅ **Alternative**: `--key-file key.txt` (file-based)
   - ⚠️ **Avoid**: `--key KEY` (visible in process list!)

3. **Audio Devices:**
   - ✅ Device names include Host API (e.g., "Microphone (WASAPI)")
   - ✅ Prevents confusion between duplicate device names

## Need Help?

- Full build instructions: [BUILD.md](BUILD.md)
- Complete documentation: [README.md](../README.md)
- User manual: Check `build/doc/manual.pdf`
- Issues: Check GitHub issues page

## Quick Reference

| Task | Command (Linux/macOS) | Command (Windows) |
|------|----------------------|-------------------|
| Build | `./build.sh` | `build.bat` |
| Clean | `./build.sh clean` | `build.bat clean` |
| Rebuild | `./build.sh rebuild` | `build.bat rebuild` |
| Run GUI | `cd build && ./fear_gui` | `cd build && fear_gui.exe` |
| Generate room key | `cd build/bin && ./fear genkey` | `cd build\bin && fear.exe genkey` |
| Generate audio key | `cd build/bin && ./audio_call genkey` | `cd build\bin && audio_call.exe genkey` |
| Generate video key | `cd build/bin && ./video_call genkey` | `cd build\bin && video_call.exe genkey` |
| Install deps (Linux) | `./build.sh deps` | N/A |
