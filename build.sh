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
    rebuild)
        clean_build
        ;;
    build)
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Usage: ./build.sh [build|clean|rebuild]"
        exit 1
        ;;
esac

# Check dependencies
print_info "Checking dependencies..."
check_dependency cmake
check_dependency gcc
check_dependency g++
print_success "All dependencies found"

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
