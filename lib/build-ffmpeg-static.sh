#!/bin/bash
# =============================================================================
# Build minimal static FFmpeg for F.E.A.R. video_call
# Run from MSYS2 MINGW64 or via build-ffmpeg-static.bat
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG_SRC="${SCRIPT_DIR}/ffmpeg-win64"
BUILD_DIR="${SCRIPT_DIR}/_ffmpeg-build-tmp"
INSTALL_DIR="${SCRIPT_DIR}/_ffmpeg-install-tmp"
LIBVPX_OUT="${SCRIPT_DIR}/libvpx"

echo "========================================"
echo "  Build Minimal Static FFmpeg"
echo "  for F.E.A.R. video_call"
echo "========================================"
echo ""

# ---- Check source ----
if [ ! -f "${FFMPEG_SRC}/configure" ]; then
    echo "ERROR: FFmpeg source not found!"
    echo "Expected 'configure' in: ${FFMPEG_SRC}"
    echo ""
    echo "Download source:"
    echo "  git clone --depth 1 https://git.ffmpeg.org/ffmpeg.git \"${FFMPEG_SRC}\""
    exit 1
fi

echo "Source:  ${FFMPEG_SRC}"
echo "Build:   ${BUILD_DIR}"
echo "Install: ${INSTALL_DIR}"
echo ""

# ---- Install build tools ----
echo "=== Installing build dependencies ==="
pacman -S --noconfirm --needed \
    make \
    mingw-w64-x86_64-gcc \
    mingw-w64-x86_64-yasm \
    mingw-w64-x86_64-nasm \
    mingw-w64-x86_64-pkg-config \
    mingw-w64-x86_64-libvpx \
    mingw-w64-x86_64-zlib
echo ""

# ---- Clean previous build ----
rm -rf "${BUILD_DIR}" "${INSTALL_DIR}"
mkdir -p "${BUILD_DIR}"

# ---- Configure ----
echo "=== Configuring FFmpeg (minimal static) ==="
cd "${BUILD_DIR}"

"${FFMPEG_SRC}/configure" \
    --prefix="${INSTALL_DIR}" \
    --enable-static \
    --disable-shared \
    --disable-programs \
    --disable-doc \
    --disable-htmlpages \
    --disable-manpages \
    --disable-podpages \
    --disable-txtpages \
    --disable-everything \
    --enable-avdevice \
    --enable-avformat \
    --enable-avcodec \
    --enable-swscale \
    --enable-avutil \
    --enable-indev=dshow \
    --enable-decoder=vp8 \
    --enable-decoder=rawvideo \
    --enable-decoder=mjpeg \
    --enable-decoder=bmp \
    --enable-encoder=libvpx_vp8 \
    --enable-demuxer=rawvideo \
    --enable-demuxer=image2 \
    --enable-muxer=rawvideo \
    --enable-protocol=file \
    --enable-filter=scale \
    --enable-filter=format \
    --enable-libvpx \
    --enable-gpl \
    --extra-cflags="-O2" \
    --extra-ldflags="-static"

echo ""

# ---- Build ----
echo "=== Building ($(nproc) threads) ==="
# Use MSYS2 make (not mingw32-make) for /c/ path translation
/usr/bin/make -j"$(nproc)"
echo ""

# ---- Install to temp dir ----
echo "=== Installing ==="
/usr/bin/make install
echo ""

# ---- Deploy: replace DLLs with static .a ----
echo "=== Deploying static libraries ==="

# Remove old shared libs and DLLs
rm -f "${FFMPEG_SRC}/lib/"*.dll.a 2>/dev/null || true
rm -f "${FFMPEG_SRC}/lib/"*.def 2>/dev/null || true
if [ -d "${FFMPEG_SRC}/bin" ]; then
    rm -f "${FFMPEG_SRC}/bin/"av*.dll 2>/dev/null || true
    rm -f "${FFMPEG_SRC}/bin/"sw*.dll 2>/dev/null || true
    rm -f "${FFMPEG_SRC}/bin/"postproc*.dll 2>/dev/null || true
fi

# Copy new static .a files
mkdir -p "${FFMPEG_SRC}/lib"
cp -f "${INSTALL_DIR}/lib/"*.a "${FFMPEG_SRC}/lib/"

# Copy fresh headers
mkdir -p "${FFMPEG_SRC}/include"
rm -rf "${FFMPEG_SRC}/include/libav"* "${FFMPEG_SRC}/include/libsw"*
cp -rf "${INSTALL_DIR}/include/"* "${FFMPEG_SRC}/include/"

# Copy pkgconfig for reference
mkdir -p "${FFMPEG_SRC}/lib/pkgconfig"
cp -f "${INSTALL_DIR}/lib/pkgconfig/"*.pc "${FFMPEG_SRC}/lib/pkgconfig/" 2>/dev/null || true

echo "Static libraries:"
ls -lh "${FFMPEG_SRC}/lib/"*.a
echo ""

# ---- Deploy libvpx for static linking ----
echo "=== Deploying libvpx ==="
mkdir -p "${LIBVPX_OUT}/lib" "${LIBVPX_OUT}/include"
cp -f /mingw64/lib/libvpx.a "${LIBVPX_OUT}/lib/"
cp -rf /mingw64/include/vpx "${LIBVPX_OUT}/include/"

echo "libvpx:"
ls -lh "${LIBVPX_OUT}/lib/"*.a
echo ""

# ---- Cleanup ----
echo "=== Cleaning up ==="
rm -rf "${BUILD_DIR}" "${INSTALL_DIR}"

# ---- Summary ----
echo ""
echo "========================================"
echo "  Build complete!"
echo "========================================"
echo ""
echo "Static FFmpeg: ${FFMPEG_SRC}/lib/"
echo "libvpx:        ${LIBVPX_OUT}/lib/"
echo ""

TOTAL=0
for f in "${FFMPEG_SRC}/lib/"*.a; do
    SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
    TOTAL=$((TOTAL + SIZE))
done
for f in "${LIBVPX_OUT}/lib/"*.a; do
    SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
    TOTAL=$((TOTAL + SIZE))
done
echo "Total static libs size: $((TOTAL / 1024 / 1024)) MB"
echo "(vs ~200 MB of DLLs)"
echo ""
echo "Now run: build.bat rebuild"
