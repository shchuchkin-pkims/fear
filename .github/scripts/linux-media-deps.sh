#!/usr/bin/env bash
# Статические libvpx, FFmpeg и SDL3 для релизной сборки video_call под Linux.
#
# Почему не системные. SDL3 в Ubuntu 22.04 нет вовсе. Системный FFmpeg
# привязал бы video_call к сонейму одной версии дистрибутива (libavcodec58
# в 22.04, 60 в 24.04, 61 и дальше): архив, собранный на одной, не запустился
# бы на соседней. Здесь всё статическое и минимальное - ровно то, что нужно
# звонку: VP8 (кодер libvpx, декодер родной), захват камеры через v4l2, MJPEG
# и сырые кадры с неё, масштабирование. Всё с -fPIC: программы проекта - PIE.
#
# Тот же набор, что lib/build-ffmpeg-static.sh собирает для Windows, только
# вход камеры v4l2 вместо dshow.
#
# usage: linux-media-deps.sh PREFIX
set -euo pipefail

PREFIX=$(realpath -m "${1:?usage: linux-media-deps.sh PREFIX}")
VPX_TAG=v1.16.0
FFMPEG_TAG=n8.0.3
SDL_TAG=release-3.4.18
JOBS=$(nproc)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$PREFIX"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

echo "=== libvpx $VPX_TAG"
git clone --quiet --depth 1 --branch "$VPX_TAG" \
    https://chromium.googlesource.com/webm/libvpx "$WORK/libvpx"
(
    cd "$WORK/libvpx"
    ./configure --prefix="$PREFIX" --enable-static --disable-shared --enable-pic \
        --disable-examples --disable-tools --disable-docs --disable-unit-tests \
        --enable-vp8 --disable-vp9 --as=nasm
    make -j"$JOBS"
    make install
)

echo "=== FFmpeg $FFMPEG_TAG"
git clone --quiet --depth 1 --branch "$FFMPEG_TAG" \
    https://github.com/FFmpeg/FFmpeg.git "$WORK/ffmpeg"
(
    cd "$WORK/ffmpeg"
    # --disable-autodetect: ничего, кроме названного. Иначе FFmpeg
    # подхватил бы всё, что нашлось на машине сборки (xcb, zlib, lzma...), и
    # архив требовал бы этого и у пользователя. Потоки - явно, они тоже
    # в списке автоопределения.
    ./configure --prefix="$PREFIX" \
        --enable-static --disable-shared --enable-pic \
        --pkg-config-flags=--static \
        --disable-programs --disable-doc --disable-network \
        --disable-autodetect --enable-pthreads \
        --disable-everything \
        --disable-avfilter --disable-swresample \
        --enable-avdevice --enable-avformat --enable-avcodec --enable-swscale \
        --enable-indev=v4l2 \
        --enable-decoder=vp8 --enable-decoder=mjpeg --enable-decoder=rawvideo \
        --enable-encoder=libvpx_vp8 --enable-libvpx
    make -j"$JOBS"
    make install
)

echo "=== SDL3 $SDL_TAG"
git clone --quiet --depth 1 --branch "$SDL_TAG" \
    https://github.com/libsdl-org/SDL.git "$WORK/sdl"
# Звонку нужны только окно и события. X11 и Wayland SDL подгружает сам во
# время работы (dlopen), поэтому статическая библиотека их не требует.
cmake -S "$WORK/sdl" -B "$WORK/sdl/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DSDL_SHARED=OFF -DSDL_STATIC=ON \
    -DSDL_TEST_LIBRARY=OFF -DSDL_TESTS=OFF -DSDL_EXAMPLES=OFF \
    -DSDL_AUDIO=OFF -DSDL_CAMERA=OFF -DSDL_JOYSTICK=OFF -DSDL_HAPTIC=OFF \
    -DSDL_HIDAPI=OFF -DSDL_SENSOR=OFF
cmake --build "$WORK/sdl/build" -j"$JOBS"
cmake --install "$WORK/sdl/build"

echo "=== done: $PREFIX"
ls -l "$PREFIX/lib"/*.a
