#!/bin/bash

# =============================================================================
# FEAR Project - Professional Build Script for Linux/Unix
# =============================================================================
# This script builds the entire FEAR project with a single command.
# All output files will be placed in: build/bin/
#
# Usage:
#   ./build.sh          - Build the project
#   ./build.sh clean    - Clean build artifacts
#   ./build.sh rebuild  - Clean and rebuild
#   ./build.sh deps     - Install build dependencies (Ubuntu/Debian)
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project directories
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_TEMP_DIR="${PROJECT_ROOT}/.build-temp"
GUI_BUILD_DIR="${PROJECT_ROOT}/gui/src/.build-temp"
OUTPUT_DIR="${PROJECT_ROOT}/build"

# =============================================================================
# Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Check if command exists
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

# Verify every dependency the project actually links against.
#
# The old check only looked for cmake/gcc/g++, so a missing -dev package
# printed "All dependencies found" and then blew up much later inside
# CMake (that is how a missing libsqlite3-dev got through). This collects
# everything that is missing and reports it in one pass.
verify_dependencies() {
    local missing_cmd=() missing_lib=() missing_other=()

    local c
    for c in cmake gcc g++ pkg-config git; do
        command -v "$c" &> /dev/null || missing_cmd+=("$c")
    done

    # pkg-config module -> package that provides it on Ubuntu/Debian
    local modules=(
        "libsodium:libsodium-dev"
        "sqlite3:libsqlite3-dev"
        "libcurl:libcurl4-openssl-dev"
        "opus:libopus-dev"
        "portaudio-2.0:portaudio19-dev"
        "libavcodec:libavcodec-dev"
        "libavformat:libavformat-dev"
        "libavutil:libavutil-dev"
        "libswscale:libswscale-dev"
        "libavdevice:libavdevice-dev"
        "libqrencode:libqrencode-dev"
        "zbar:libzbar-dev"
        "sdl3:built from source by ./build.sh deps"
    )
    local entry mod pkg
    for entry in "${modules[@]}"; do
        mod="${entry%%:*}"
        pkg="${entry#*:}"
        pkg-config --exists "$mod" 2>/dev/null || missing_lib+=("$mod -> $pkg")
    done

    # Qt6 ships CMake config packages rather than pkg-config files.
    if ! ls -d /usr/lib/*/cmake/Qt6Widgets &> /dev/null && ! command -v qmake6 &> /dev/null; then
        missing_other+=("Qt6 (Widgets/Network/Sql/Concurrent) -> qt6-base-dev qt6-base-dev-tools")
    fi

    # Qt's SQLite driver is a separate package and is NOT pulled in by
    # qt6-base-dev. Without it the GUI compiles fine and then fails at
    # runtime, when it opens the local message history.
    if ! ls /usr/lib/*/qt6/plugins/sqldrivers/libqsqlite.so &> /dev/null; then
        missing_other+=("Qt6 SQLite driver -> libqt6sql6-sqlite")
    fi

    if [ ${#missing_cmd[@]} -eq 0 ] && [ ${#missing_lib[@]} -eq 0 ] && [ ${#missing_other[@]} -eq 0 ]; then
        print_success "All dependencies found"
        return 0
    fi

    print_error "Missing dependencies:"
    local m
    for m in "${missing_cmd[@]}";   do echo "    command: $m"; done
    for m in "${missing_lib[@]}";   do echo "    library: $m"; done
    for m in "${missing_other[@]}"; do echo "    other:   $m"; done
    echo ""
    print_info "Install them with: ./build.sh deps"
    return 1
}

# Clean build artifacts
clean_build() {
    print_header "Cleaning Build Artifacts"

    print_info "Removing temporary build directories..."
    rm -rf "${BUILD_TEMP_DIR}"
    rm -rf "${GUI_BUILD_DIR}"

    print_info "Removing intermediate files..."
    # Keep build/bin and build/doc with executables, remove cmake cache
    find "${BUILD_TEMP_DIR}" -name "CMakeCache.txt" -delete 2>/dev/null || true
    find "${BUILD_TEMP_DIR}" -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true

    print_success "Clean completed"
}

# Build main project (console apps)
build_main_project() {
    print_header "Building Main Project"

    cd "${PROJECT_ROOT}"

    # Create temporary build directory
    mkdir -p "${BUILD_TEMP_DIR}"
    cd "${BUILD_TEMP_DIR}"

    print_info "Configuring with CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Release

    print_info "Building..."
    cmake --build . --config Release -j$(nproc)

    print_success "Main project built successfully"
}

# Build GUI
build_gui() {
    print_header "Building GUI Application"

    cd "${PROJECT_ROOT}/gui/src"

    # Create temporary build directory
    mkdir -p "${GUI_BUILD_DIR}"
    cd "${GUI_BUILD_DIR}"

    print_info "Configuring GUI with CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Release

    print_info "Building GUI..."
    cmake --build . --config Release -j$(nproc)

    print_success "GUI built successfully"
}

# Display build results
show_results() {
    print_header "Build Complete!"

    echo "All executables are located in: ${OUTPUT_DIR}/bin/"
    echo ""
    echo "Built applications:"

    if [ -d "${OUTPUT_DIR}/bin" ]; then
        for file in "${OUTPUT_DIR}/bin"/*; do
            if [ -f "$file" ] && [ -x "$file" ]; then
                filename=$(basename "$file")
                filesize=$(du -h "$file" | cut -f1)
                echo "  • $filename ($filesize)"
            fi
        done
    fi

    echo ""
    echo "Documentation: ${OUTPUT_DIR}/doc/"
    echo ""
}

# =============================================================================
# Main Script
# =============================================================================

print_header "FEAR Project Build System"

# Handle command line arguments
case "${1:-build}" in
    clean)
        clean_build
        print_success "All build artifacts cleaned"
        exit 0
        ;;
    deps)
        print_header "Installing Build Dependencies"
        print_info "Installing packages (requires sudo)..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential cmake pkg-config git \
            libsodium-dev libcurl4-openssl-dev libsqlite3-dev \
            libopus-dev portaudio19-dev \
            libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libavdevice-dev \
            libvpx-dev \
            qt6-base-dev qt6-base-dev-tools libqt6sql6-sqlite \
            libqrencode-dev libzbar-dev
        # SDL3 is not yet in Ubuntu repos — check if installed
        if ! pkg-config --exists sdl3 2>/dev/null; then
            print_info "SDL3 not found in system packages, building from source..."
            # SDL refuses to configure unless it finds a window system. The
            # Wayland set alone is not enough: if any Wayland piece is missing
            # (or the machine has no compositor headers at all) SDL falls back
            # to X11, and without the X11 headers below it aborts with
            # "could not find X11 or Wayland development libraries".
            sudo apt-get install -y \
                libx11-dev libxext-dev libxrandr-dev libxcursor-dev \
                libxi-dev libxfixes-dev libxss-dev \
                libwayland-dev libwayland-bin wayland-protocols \
                libxkbcommon-dev libdecor-0-dev \
                libpulse-dev libasound2-dev
            SDL_TMP=$(mktemp -d)
            git clone --depth 1 https://github.com/libsdl-org/SDL.git -b release-3.2.x "${SDL_TMP}/SDL"
            # On a headless box (server, Pi without a desktop) there is no
            # window system to find and the check above is not wanted:
            #   FEAR_SDL_HEADLESS=1 ./build.sh deps
            SDL_EXTRA_FLAGS=""
            if [ -n "${FEAR_SDL_HEADLESS:-}" ]; then
                print_info "FEAR_SDL_HEADLESS set — building SDL without X11/Wayland video"
                SDL_EXTRA_FLAGS="-DSDL_UNIX_CONSOLE_BUILD=ON"
            fi
            if ! cmake -S "${SDL_TMP}/SDL" -B "${SDL_TMP}/SDL/build" \
                    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
                    ${SDL_EXTRA_FLAGS}; then
                print_error "SDL configuration failed."
                print_info "On a desktop machine: check that the X11/Wayland -dev packages above installed."
                print_info "On a headless machine: re-run with FEAR_SDL_HEADLESS=1 ./build.sh deps"
                rm -rf "${SDL_TMP}"
                exit 1
            fi
            cmake --build "${SDL_TMP}/SDL/build" -j$(nproc)
            sudo cmake --install "${SDL_TMP}/SDL/build"
            rm -rf "${SDL_TMP}"
            print_success "SDL3 built and installed from source"
        else
            print_success "SDL3 already installed"
        fi
        # Prove it rather than assume it: the whole point of this target is
        # that the next ./build.sh must not fail on a missing package.
        print_info "Verifying..."
        verify_dependencies || exit 1
        print_success "All dependencies installed"
        exit 0
        ;;
    rebuild)
        clean_build
        ;;
    build)
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Usage: ./build.sh [build|clean|rebuild|deps]"
        exit 1
        ;;
esac

# Check dependencies
print_info "Checking dependencies..."
verify_dependencies || exit 1

# Create output directory
mkdir -p "${OUTPUT_DIR}/bin"
mkdir -p "${OUTPUT_DIR}/doc"

# Build everything
build_main_project
build_gui

# Clean temporary files (keep only final binaries)
print_info "Cleaning temporary build files..."
rm -rf "${BUILD_TEMP_DIR}"
rm -rf "${GUI_BUILD_DIR}"

# Show results
show_results

print_success "Build process completed successfully!"
echo ""
