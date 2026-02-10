cmake_minimum_required(VERSION 3.12)
project(video_call C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Common compile flags
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Source files: video_call own sources + reused audio sources
set(SOURCES
    src/video_call.c
    src/video_capture.c
    src/video_codec.c
    src/video_display.c
    src/video_fragment.c
    src/video_quality.c
    # Reused audio sources (compiled directly into video_call target)
    ${CMAKE_SOURCE_DIR}/audio_call/src/audio_crypto.c
    ${CMAKE_SOURCE_DIR}/audio_call/src/audio_network.c
    ${CMAKE_SOURCE_DIR}/audio_call/src/audio_ring.c
    ${CMAKE_SOURCE_DIR}/audio_call/src/audio_codec.c
    ${CMAKE_SOURCE_DIR}/audio_call/src/audio_hub.c
)

add_executable(video_call ${SOURCES})

# Include directories
target_include_directories(video_call PRIVATE
    include
    ${CMAKE_SOURCE_DIR}/audio_call/include
)

if(WIN32)
    # Windows library paths (from parent CMake or defaults)
    if(NOT DEFINED LIBSODIUM_ROOT)
        set(LIBSODIUM_ROOT "${CMAKE_SOURCE_DIR}/lib/libsodium-win64")
    endif()
    if(NOT DEFINED OPUS_ROOT)
        set(OPUS_ROOT "${CMAKE_SOURCE_DIR}/lib/opus-1.5.2")
    endif()
    if(NOT DEFINED PORTAUDIO_ROOT)
        set(PORTAUDIO_ROOT "${CMAKE_SOURCE_DIR}/lib/portaudio")
    endif()
    if(NOT DEFINED FFMPEG_ROOT)
        set(FFMPEG_ROOT "${CMAKE_SOURCE_DIR}/lib/ffmpeg-win64")
    endif()
    if(NOT DEFINED SDL3_ROOT)
        set(SDL3_ROOT "${CMAKE_SOURCE_DIR}/lib/SDL3-win64")
    endif()

    # Include directories
    target_include_directories(video_call PRIVATE
        "${LIBSODIUM_ROOT}/include"
        "${OPUS_ROOT}/include"
        "${PORTAUDIO_ROOT}/include"
        "${FFMPEG_ROOT}/include"
        "${SDL3_ROOT}/include"
    )

    # Find libraries
    # libsodium
    if(EXISTS "${LIBSODIUM_ROOT}/lib/libsodium.a")
        set(SODIUM_LIB "${LIBSODIUM_ROOT}/lib/libsodium.a")
    elseif(EXISTS "${LIBSODIUM_ROOT}/lib/libsodium.dll.a")
        set(SODIUM_LIB "${LIBSODIUM_ROOT}/lib/libsodium.dll.a")
    else()
        message(FATAL_ERROR "libsodium library not found in ${LIBSODIUM_ROOT}/lib")
    endif()

    # opus
    if(EXISTS "${OPUS_ROOT}/build/libopus.a")
        set(OPUS_LIB "${OPUS_ROOT}/build/libopus.a")
    else()
        message(FATAL_ERROR "opus library not found in ${OPUS_ROOT}/build")
    endif()

    # portaudio
    if(EXISTS "${PORTAUDIO_ROOT}/build/libportaudio.a")
        set(PORTAUDIO_LIB "${PORTAUDIO_ROOT}/build/libportaudio.a")
    else()
        message(FATAL_ERROR "portaudio library not found in ${PORTAUDIO_ROOT}/build")
    endif()

    # FFmpeg libraries — static (.a) preferred, fallback to import (.dll.a)
    set(FFMPEG_LIB_DIR "${FFMPEG_ROOT}/lib")
    set(FFMPEG_LIBS "")
    set(FFMPEG_STATIC OFF)
    foreach(_fflib avdevice avformat avcodec swscale avutil)
        if(EXISTS "${FFMPEG_LIB_DIR}/lib${_fflib}.a")
            list(APPEND FFMPEG_LIBS "${FFMPEG_LIB_DIR}/lib${_fflib}.a")
            set(FFMPEG_STATIC ON)
        elseif(EXISTS "${FFMPEG_LIB_DIR}/lib${_fflib}.dll.a")
            list(APPEND FFMPEG_LIBS "${FFMPEG_LIB_DIR}/lib${_fflib}.dll.a")
        else()
            message(FATAL_ERROR "FFmpeg library lib${_fflib} not found in ${FFMPEG_LIB_DIR}")
        endif()
    endforeach()

    # When FFmpeg is linked statically, its internal dependencies must be
    # resolved explicitly.  libavcodec ships a built-in VP8 encoder/decoder
    # but may also be compiled with --enable-libvpx; link libvpx if present.
    if(FFMPEG_STATIC)
        message(STATUS "FFmpeg: using static libraries")

        # libvpx (VP8 codec used by FFmpeg) — optional, only if FFmpeg was
        # built with --enable-libvpx
        if(NOT DEFINED LIBVPX_ROOT)
            set(LIBVPX_ROOT "${CMAKE_SOURCE_DIR}/lib/libvpx")
        endif()
        if(EXISTS "${LIBVPX_ROOT}/lib/libvpx.a")
            list(APPEND FFMPEG_LIBS "${LIBVPX_ROOT}/lib/libvpx.a")
            target_include_directories(video_call PRIVATE "${LIBVPX_ROOT}/include")
            message(STATUS "  Found libvpx at: ${LIBVPX_ROOT}")
        endif()

        # zlib — FFmpeg may need it for internal compression
        find_library(ZLIB_LIB NAMES libz.a z PATHS "${FFMPEG_LIB_DIR}" "${CMAKE_SOURCE_DIR}/lib/zlib/lib")
        if(ZLIB_LIB)
            list(APPEND FFMPEG_LIBS "${ZLIB_LIB}")
        endif()

        # liblzma — FFmpeg may use it
        find_library(LZMA_LIB NAMES liblzma.a lzma PATHS "${FFMPEG_LIB_DIR}")
        if(LZMA_LIB)
            list(APPEND FFMPEG_LIBS "${LZMA_LIB}")
        endif()

        # Windows system libraries required by static FFmpeg (dshow, mf, etc.)
        list(APPEND FFMPEG_LIBS
            bcrypt secur32 strmiids mfplat mfuuid oleaut32 shlwapi
            user32 gdi32 advapi32 shell32
        )
    else()
        message(STATUS "FFmpeg: using shared libraries (DLLs required at runtime)")
    endif()

    # SDL3
    if(EXISTS "${SDL3_ROOT}/lib/libSDL3.a")
        set(SDL3_LIB "${SDL3_ROOT}/lib/libSDL3.a")
    elseif(EXISTS "${SDL3_ROOT}/lib/libSDL3.dll.a")
        set(SDL3_LIB "${SDL3_ROOT}/lib/libSDL3.dll.a")
    else()
        message(FATAL_ERROR "SDL3 library not found in ${SDL3_ROOT}/lib")
    endif()

    target_link_libraries(video_call PRIVATE
        "${SODIUM_LIB}"
        "${OPUS_LIB}"
        "${PORTAUDIO_LIB}"
        ${FFMPEG_LIBS}
        "${SDL3_LIB}"
        ssp ws2_32 winmm ole32 uuid setupapi imm32 version
    )

    set_target_properties(video_call PROPERTIES
        LINK_FLAGS "-static -static-libgcc -static-libstdc++"
    )

else()
    # Linux - use system libraries via pkg-config
    find_package(PkgConfig REQUIRED)

    pkg_check_modules(LIBSODIUM REQUIRED libsodium)
    target_include_directories(video_call PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
    target_link_libraries(video_call PRIVATE ${LIBSODIUM_LIBRARIES})

    pkg_check_modules(OPUS REQUIRED opus)
    target_include_directories(video_call PRIVATE ${OPUS_INCLUDE_DIRS})
    target_link_libraries(video_call PRIVATE ${OPUS_LIBRARIES})

    pkg_check_modules(PORTAUDIO REQUIRED portaudio-2.0)
    target_include_directories(video_call PRIVATE ${PORTAUDIO_INCLUDE_DIRS})
    target_link_libraries(video_call PRIVATE ${PORTAUDIO_LIBRARIES})

    # FFmpeg libraries
    pkg_check_modules(LIBAVCODEC REQUIRED libavcodec)
    pkg_check_modules(LIBAVDEVICE REQUIRED libavdevice)
    pkg_check_modules(LIBAVFORMAT REQUIRED libavformat)
    pkg_check_modules(LIBSWSCALE REQUIRED libswscale)
    pkg_check_modules(LIBAVUTIL REQUIRED libavutil)

    target_include_directories(video_call PRIVATE
        ${LIBAVCODEC_INCLUDE_DIRS}
        ${LIBAVDEVICE_INCLUDE_DIRS}
        ${LIBAVFORMAT_INCLUDE_DIRS}
        ${LIBSWSCALE_INCLUDE_DIRS}
        ${LIBAVUTIL_INCLUDE_DIRS}
    )
    target_link_libraries(video_call PRIVATE
        ${LIBAVDEVICE_LIBRARIES}
        ${LIBAVFORMAT_LIBRARIES}
        ${LIBAVCODEC_LIBRARIES}
        ${LIBSWSCALE_LIBRARIES}
        ${LIBAVUTIL_LIBRARIES}
    )

    # SDL3
    pkg_check_modules(SDL3 REQUIRED sdl3)
    target_include_directories(video_call PRIVATE ${SDL3_INCLUDE_DIRS})
    target_link_libraries(video_call PRIVATE ${SDL3_LIBRARIES})

    # Additional Linux libraries
    target_link_libraries(video_call PRIVATE pthread m)

    message(STATUS "Using system FFmpeg: ${LIBAVCODEC_VERSION}")
    message(STATUS "Using system SDL3: ${SDL3_VERSION}")
endif()
