#!/bin/bash

# Script to create a release ZIP archive for F.E.A.R. project
# Usage: ./pack_release.sh [version]
# Example: ./pack_release.sh 0.3.0

set -e

VERSION=${1:-"latest"}
ARCH=$(uname -m)
OS="linux"

# Normalize architecture name
if [ "$ARCH" = "x86_64" ]; then
    ARCH="x86_64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

OUTPUT_NAME="fear-${OS}-${ARCH}.zip"

echo "========================================="
echo "  F.E.A.R. Release Packager"
echo "========================================="
echo "Version: $VERSION"
echo "Platform: $OS-$ARCH"
echo "Output: $OUTPUT_NAME"
echo ""

# Check if build directory exists
if [ ! -d "build" ]; then
    echo "Error: build/ directory not found!"
    echo "Please run ./build.sh first to build the project."
    exit 1
fi

# Check if zip is installed
if ! command -v zip &> /dev/null; then
    echo "Error: zip utility not found!"
    echo "Please install it: sudo apt-get install zip"
    exit 1
fi

# Create temporary directory for packaging
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "→ Preparing files..."

# Copy files to temporary directory
mkdir -p "$TEMP_DIR/bin"
cp -r build/bin/* "$TEMP_DIR/bin/" 2>/dev/null || true

# Copy GUI if exists
if [ -f "build/fear_gui" ]; then
    cp build/fear_gui "$TEMP_DIR/" 2>/dev/null || true
    echo "  ✓ GUI included"
fi

# Copy only manual.pdf from documentation
if [ -f "doc/manual.pdf" ]; then
    mkdir -p "$TEMP_DIR/doc"
    cp doc/manual.pdf "$TEMP_DIR/doc/" 2>/dev/null || true
    echo "  ✓ manual.pdf included"
fi

# Create the ZIP archive
echo ""
echo "→ Creating archive..."

# Save current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$TEMP_DIR"
zip -r "$SCRIPT_DIR/$OUTPUT_NAME" .
cd "$SCRIPT_DIR"

FILE_SIZE=$(du -h "$OUTPUT_NAME" | cut -f1)
echo ""
echo "========================================="
echo "  ✓ Release package created!"
echo "========================================="
echo "File: $OUTPUT_NAME"
echo "Size: $FILE_SIZE"
echo ""
echo "Next steps:"
echo "1. Test the archive:"
echo "   unzip -l $OUTPUT_NAME"
echo ""
echo "2. Upload to GitHub Release:"
echo "   - Go to https://github.com/shchuchkin-pkims/fear/releases/new"
echo "   - Create tag: v$VERSION"
echo "   - Upload: $OUTPUT_NAME"
echo ""
