#!/usr/bin/env bash
# Раскладывает зависимости из пакетов MSYS2 по lib/ - туда, где их ищет
# сборка под Windows (корневой CMakeLists.txt и подпроекты звонков).
#
# Разработчик кладёт в lib/ готовые сборки руками, в git её нет - 464 МБ.
# Поэтому CI до 0.6.0 собирал под Windows только fear и fear_gui, без
# звонков и без программы обновления. Здесь те же библиотеки берутся из
# MSYS2 и раскладываются так, как лежат у разработчика, - CMake не знает
# разницы. FFmpeg минимальный и статический, его собирает
# lib/build-ffmpeg-static.sh, как и у разработчика.
#
# Запускать из MSYS2 MINGW64, из корня репозитория.
set -euo pipefail

M=/mingw64
L=lib

mkdir -p "$L/opus-1.5.2/include" "$L/opus-1.5.2/build"
cp "$M"/include/opus/*.h "$L/opus-1.5.2/include/"
cp "$M/lib/libopus.a" "$L/opus-1.5.2/build/"

mkdir -p "$L/portaudio/include" "$L/portaudio/build"
cp "$M/include/portaudio.h" "$L/portaudio/include/"
cp "$M/lib/libportaudio.a" "$L/portaudio/build/"

mkdir -p "$L/libsodium-win64/include" "$L/libsodium-win64/lib"
cp -r "$M/include/sodium.h" "$M/include/sodium" "$L/libsodium-win64/include/"
cp "$M/lib/libsodium.a" "$M/lib/libsodium.dll.a" "$L/libsodium-win64/lib/"

# SDL3 - DLL рядом с video_call.exe, как у разработчика: только библиотека
# импорта, чтобы CMake не выбрал статическую, если пакет её принесёт.
mkdir -p "$L/SDL3-win64/include" "$L/SDL3-win64/lib" "$L/SDL3-win64/bin"
cp -r "$M/include/SDL3" "$L/SDL3-win64/include/"
cp "$M/lib/libSDL3.dll.a" "$L/SDL3-win64/lib/"
cp "$M/bin/SDL3.dll" "$L/SDL3-win64/bin/"

mkdir -p "$L/curl-8.15.0_5-win64-mingw/include" "$L/curl-8.15.0_5-win64-mingw/lib"
cp -r "$M/include/curl" "$L/curl-8.15.0_5-win64-mingw/include/"
cp "$M/lib/libcurl.dll.a" "$L/curl-8.15.0_5-win64-mingw/lib/"

echo "lib/ staged from MSYS2:"
find "$L" -maxdepth 3 \( -name '*.a' -o -name '*.dll' \) | sort
