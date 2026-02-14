# FEAR Project - Build Instructions

Professional build system for cross-platform compilation.

## Quick Start

### Linux/macOS

```bash
./build.sh
```

### Windows

```batch
build.bat
```

That's it! All executables will be in `build/bin/` directory.

## Build Commands

### Standard Build

**Linux/macOS:**
```bash
./build.sh
```

**Windows:**
```batch
build.bat
```

### Install Dependencies (Linux)

```bash
./build.sh deps
```

Installs all required packages including FFmpeg, SDL3, libvpx, Qt6, libsodium, Opus, PortAudio and more. Automatically builds SDL3 from source if not available in repos.

### Clean Build Artifacts

Remove all temporary files (keeps compiled binaries):

**Linux/macOS:**
```bash
./build.sh clean
```

**Windows:**
```batch
build.bat clean
```

### Rebuild from Scratch

Clean and rebuild everything:

**Linux/macOS:**
```bash
./build.sh rebuild
```

**Windows:**
```batch
build.bat rebuild
```

## Output Structure

After building, your project structure will be:

```
fear-main/
├── build/
│   ├── fear_gui.exe      ← GUI application (with Qt files)
│   ├── *.dll             ← Qt libraries (Windows)
│   ├── platforms/        ← Qt plugins
│   ├── bin/              ← Console utilities
│   │   ├── fear.exe      ← Client-server
│   │   ├── audio_call.exe
│   │   ├── video_call.exe
│   │   ├── key-exchange.exe
│   │   ├── updater.exe
│   │   └── *.dll, *.conf, etc.
│   └── doc/
│       └── manual.pdf
└── .build-temp/          ← Temporary files (auto-cleaned)
```

## Requirements

### Linux/Ubuntu

```bash
# Automatic (recommended):
./build.sh deps

# Or manual:
sudo apt-get update
sudo apt-get install build-essential cmake git pkg-config
sudo apt-get install qt6-base-dev libsodium-dev libcurl4-openssl-dev
sudo apt-get install libopus-dev portaudio19-dev
sudo apt-get install libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libavdevice-dev
sudo apt-get install libvpx-dev libsdl3-dev
```

> **Note:** SDL3 may not be in your distro's repos yet. `./build.sh deps` builds it from source automatically if needed.

### Windows

1. **MinGW-w64**: Download from [winlibs.com](https://winlibs.com/) or [MSYS2](https://www.msys2.org/)
2. **CMake**: Download from [cmake.org](https://cmake.org/download/)
3. **Qt6**: Download from [qt.io](https://www.qt.io/download)
4. **Libraries**: Place in `lib/` directory (see main README.md)

Make sure all tools are in your PATH.

## Build System Features

### ✅ Professional Best Practices

- **Out-of-source build**: CMake builds in temporary directories
- **Clean separation**: Source code never polluted with build artifacts
- **Automatic cleanup**: Temporary files removed after build
- **Single command**: Build entire project with one script
- **Cross-platform**: Same workflow on Linux and Windows
- **Parallel compilation**: Uses all CPU cores for faster builds
- **Error handling**: Clear error messages and build status

### 🗂️ Directory Structure

```
Project Root
├── build/                    ← Final outputs (committed to git)
│   ├── bin/                 ← All executables
│   └── doc/                 ← Documentation
├── .build-temp/             ← Temporary CMake files (auto-deleted)
├── gui/src/.build-temp/     ← GUI temp files (auto-deleted)
└── lib/                     ← External libraries (not in git)
```

### 🔧 What Happens During Build

1. **Dependency Check**: Verifies cmake, gcc, g++ are installed
2. **Create Directories**: Sets up `build/bin` and `build/doc`
3. **Configure**: CMake generates build files in temporary directory
4. **Compile**: Builds all components with parallel compilation
5. **Copy Resources**: Moves DLLs, configs, docs to `build/`
6. **Cleanup**: Removes all temporary build files
7. **Show Results**: Lists all built executables

### 🧹 What Gets Cleaned

**Automatic cleanup after build:**
- `.build-temp/` - CMake cache and intermediate files
- `gui/src/.build-temp/` - GUI build artifacts
- All `CMakeFiles/`, `*.cmake`, object files

**What stays:**
- `build/bin/` - Your compiled programs
- `build/doc/` - Documentation
- All source code

## Troubleshooting

### Build fails with "cmake: command not found"

Install CMake:
- **Ubuntu/Debian:** `sudo apt-get install cmake`
- **Windows:** Download from cmake.org and add to PATH

### Build fails with "Qt6 not found"

Install Qt6:
- **Ubuntu/Debian:** `sudo apt-get install qt6-base-dev`
- **Windows:** Download Qt6 installer and set `CMAKE_PREFIX_PATH`

### Build fails with missing libraries

Check that all external libraries are in `lib/` directory.
See main README.md for library download links.

### Windows: "gcc: command not found"

Install MinGW-w64 and add `C:\mingw64\bin` to PATH.

## Advanced Usage

### Manual CMake Build

If you need custom CMake options:

```bash
mkdir .build-temp
cd .build-temp
cmake .. -DCMAKE_BUILD_TYPE=Release [YOUR_OPTIONS]
cmake --build . -j$(nproc)
```

### Debug Build

For development with debug symbols:

```bash
mkdir .build-temp
cd .build-temp
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .
```

### Specify Compiler

```bash
mkdir .build-temp
cd .build-temp
cmake .. -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=g++-12
cmake --build .
```

## Integration with IDEs

### Visual Studio Code

1. Install "CMake Tools" extension
2. Open project folder
3. Select kit (compiler)
4. Press F7 or click "Build" in status bar

### Qt Creator

1. Open `CMakeLists.txt` as project
2. Configure kit
3. Build → Build All (Ctrl+B)

### CLion

1. Open project directory
2. CLion auto-detects CMake
3. Build → Build Project (Ctrl+F9)

## FAQ

**Q: Why two different build directories?**
A: `.build-temp/` contains CMake's temporary files (deleted after build). `build/` contains your final executables (kept for distribution).

**Q: Can I build just one component?**
A: Yes, use manual CMake build and specify target: `cmake --build . --target fear`

**Q: Where are intermediate .o files?**
A: In `.build-temp/` which is automatically cleaned after successful build.

**Q: How to create release package?**
A: Simply zip the `build/` directory - it contains everything needed to run.

## Best Practices Implemented

This build system follows industry-standard practices:

1. ✅ **Separation of concerns**: Source code separate from build artifacts
2. ✅ **Reproducible builds**: Same commands produce same results
3. ✅ **Fast builds**: Parallel compilation, incremental builds
4. ✅ **Clean workspace**: No clutter in source directories
5. ✅ **Easy distribution**: Everything in `build/` ready to ship
6. ✅ **Cross-platform**: Works on Linux, macOS, Windows
7. ✅ **Error recovery**: Easy to clean and rebuild
8. ✅ **Documentation**: Clear structure and commands

## References

- [CMake Best Practices](https://cmake.org/cmake/help/latest/guide/tutorial/index.html)
- [Out-of-source builds](https://cmake.org/cmake/help/latest/guide/user-interaction/index.html)
- [Professional C++ Build Systems](https://www.incredibuild.com/blog/cmake-best-practices)
