# Build Instructions

## Quick Start

**Linux:**
```bash
./build.sh deps    # install all dependencies
./build.sh         # build
```

**Windows:**
```batch
build.bat
```

All executables will be in `build/bin/`.

---

## Requirements

### Linux (Ubuntu/Debian)

```bash
# Automatic (recommended):
./build.sh deps

# Or manual:
sudo apt-get update
sudo apt-get install build-essential cmake git pkg-config
sudo apt-get install qt6-base-dev libsodium-dev libcurl4-openssl-dev
sudo apt-get install libopus-dev portaudio19-dev
sudo apt-get install libavcodec-dev libavformat-dev libavutil-dev \
    libswscale-dev libavdevice-dev
sudo apt-get install libvpx-dev libsdl3-dev
```

> **Note:** SDL3 may not be in your distro's repos. `./build.sh deps` builds it from source automatically if needed.

### Windows

1. **MinGW-w64** — download from [winlibs.com](https://winlibs.com/) or [MSYS2](https://www.msys2.org/)
2. **CMake 3.12+** — download from [cmake.org](https://cmake.org/download/)
3. **Qt6 6.2+** — download from [qt.io](https://www.qt.io/download)
4. **Libraries** — place in `lib/` directory:
   - `lib/libsodium-win64/` — libsodium headers and static/import libs
   - `lib/curl-win64/` — libcurl
   - `lib/opus-win64/` — Opus codec
   - `lib/portaudio-win64/` — PortAudio
   - `lib/ffmpeg-win64/` — FFmpeg (see [BUILD_FFMPEG.md](../lib/BUILD_FFMPEG.md) for minimal static build)
   - `lib/libvpx/` — VP8 codec
   - `lib/SDL3-win64/` — SDL3

Make sure MinGW, CMake, and Qt are in your PATH.

---

## Build Commands

### Standard Build

```bash
# Linux
./build.sh

# Windows
build.bat
```

### Install Dependencies (Linux only)

```bash
./build.sh deps
```

### Clean Build Artifacts

```bash
./build.sh clean       # Linux
build.bat clean        # Windows
```

### Full Rebuild

```bash
./build.sh rebuild     # Linux
build.bat rebuild      # Windows
```

---

## Output Structure

```
build/
├── fear_gui            # GUI application
├── *.dll               # Qt/runtime libraries (Windows)
├── platforms/           # Qt platform plugins (Windows)
├── bin/
│   ├── fear            # Console client/server
│   ├── audio_call      # Voice call utility
│   ├── video_call      # Video call utility
│   ├── key-exchange    # Key exchange utility
│   ├── updater         # Update manager
│   └── updater.conf    # Updater configuration
└── doc/
    └── manual.pdf      # User manual (if available)
```

---

## Manual CMake Build

```bash
mkdir .build-temp && cd .build-temp
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

### Debug Build

```bash
mkdir .build-temp && cd .build-temp
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .
```

### Custom Compiler

```bash
cmake .. -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=g++-12
```

---

## IDE Integration

### Visual Studio Code
1. Install "CMake Tools" extension
2. Open project folder, select kit, press F7

### Qt Creator
1. Open `CMakeLists.txt` as project
2. Configure kit, Build > Build All (Ctrl+B)

### CLion
1. Open project directory (auto-detects CMake)
2. Build > Build Project (Ctrl+F9)

---

## Reducing Windows Build Size

Pre-built FFmpeg DLLs are ~238 MB. The project only uses VP8, MJPEG, dshow, and swscale. A static build with `--disable-everything` reduces this to ~5-10 MB.

See [lib/BUILD_FFMPEG.md](../lib/BUILD_FFMPEG.md) for step-by-step instructions.

---

## Troubleshooting

### `cmake: command not found`
Install CMake: `sudo apt-get install cmake` (Linux) or download from cmake.org (Windows).

### `Qt6 not found`
Install Qt6: `sudo apt-get install qt6-base-dev` (Linux) or set `CMAKE_PREFIX_PATH` to Qt installation (Windows).

### Missing libraries on Windows
Verify all library directories exist in `lib/` with correct structure (headers in `include/`, libs in `lib/`).

### `gcc: command not found` (Windows)
Install MinGW-w64 and add its `bin/` to PATH.

### Linking errors with FFmpeg on Windows
Static FFmpeg linking requires system libraries (`bcrypt`, `strmiids`, `mfplat`, etc.). These are already configured in `video_call/CMakeLists.txt`. If something is missing, add it to the `FFMPEG_STATIC` section.
