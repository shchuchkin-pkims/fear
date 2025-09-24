cmake_minimum_required(VERSION 3.12)
project(audio_call C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Общие флаги компиляции
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Указываем конкретные исходные файлы
#set(SOURCES audio_call.c)
file(GLOB SOURCES "src/*.c")

# Создание исполняемого файла
add_executable(audio_call ${SOURCES})

# Платформо-зависимые настройки
if(WIN32)
    # Получаем пути к библиотекам из родительского CMake
    if(NOT DEFINED LIBSODIUM_ROOT)
        set(LIBSODIUM_ROOT "${CMAKE_SOURCE_DIR}/../lib/libsodium-win64")
    endif()
    
    if(NOT DEFINED OPUS_ROOT)
        set(OPUS_ROOT "${CMAKE_SOURCE_DIR}/../lib/opus-1.5.2")
    endif()
    
    if(NOT DEFINED PORTAUDIO_ROOT)
        set(PORTAUDIO_ROOT "${CMAKE_SOURCE_DIR}/../lib/portaudio")
    endif()

    # Установка путей
    set(SODIUM_INCLUDE_DIR "${LIBSODIUM_ROOT}/include")
    set(SODIUM_LIBRARY_DIR "${LIBSODIUM_ROOT}/lib")
    
    set(OPUS_INCLUDE_DIR "${OPUS_ROOT}/include")
    set(OPUS_LIBRARY_DIR "${OPUS_ROOT}/build")
    
    set(PORTAUDIO_INCLUDE_DIR "${PORTAUDIO_ROOT}/include")
    set(PORTAUDIO_LIBRARY_DIR "${PORTAUDIO_ROOT}/build")

    # Проверка существования библиотек
    if(NOT EXISTS "${SODIUM_INCLUDE_DIR}")
        message(FATAL_ERROR "libsodium include not found: ${SODIUM_INCLUDE_DIR}")
    endif()
    
    if(NOT EXISTS "${OPUS_INCLUDE_DIR}")
        message(FATAL_ERROR "opus include not found: ${OPUS_INCLUDE_DIR}")
    endif()
    
    if(NOT EXISTS "${PORTAUDIO_INCLUDE_DIR}")
        message(FATAL_ERROR "portaudio include not found: ${PORTAUDIO_INCLUDE_DIR}")
    endif()

    # Настройка include директорий
    target_include_directories(audio_call PRIVATE 
        "${SODIUM_INCLUDE_DIR}"
        "${OPUS_INCLUDE_DIR}"
        "${PORTAUDIO_INCLUDE_DIR}"
    )

    # Поиск библиотек с проверкой
    if(EXISTS "${SODIUM_LIBRARY_DIR}/libsodium.a")
        set(SODIUM_LIB "${SODIUM_LIBRARY_DIR}/libsodium.a")
    elseif(EXISTS "${SODIUM_LIBRARY_DIR}/libsodium.dll.a")
        set(SODIUM_LIB "${SODIUM_LIBRARY_DIR}/libsodium.dll.a")
    else()
        message(FATAL_ERROR "libsodium library not found in ${SODIUM_LIBRARY_DIR}")
    endif()

    if(EXISTS "${OPUS_LIBRARY_DIR}/libopus.a")
        set(OPUS_LIB "${OPUS_LIBRARY_DIR}/libopus.a")
    else()
        message(FATAL_ERROR "opus library not found in ${OPUS_LIBRARY_DIR}")
    endif()

    if(EXISTS "${PORTAUDIO_LIBRARY_DIR}/libportaudio.a")
        set(PORTAUDIO_LIB "${PORTAUDIO_LIBRARY_DIR}/libportaudio.a")
    else()
        message(FATAL_ERROR "portaudio library not found in ${PORTAUDIO_LIBRARY_DIR}")
    endif()

    # Линковка библиотек
    target_link_libraries(audio_call PRIVATE 
        "${SODIUM_LIB}"
        "${OPUS_LIB}"
        "${PORTAUDIO_LIB}"
        ws2_32
        winmm
        ole32
        uuid
        setupapi
    )

    # Статическая линковка
    set_target_properties(audio_call PROPERTIES
        LINK_FLAGS "-static -static-libgcc -static-libstdc++"
    )

else()
    # Для Linux (если понадобится)
    find_package(PkgConfig)
    
    # Поиск libsodium
    pkg_check_modules(LIBSODIUM libsodium)
    if(LIBSODIUM_FOUND)
        target_include_directories(audio_call PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
        target_link_libraries(audio_call PRIVATE ${LIBSODIUM_LIBRARIES})
    else()
        find_library(SODIUM_LIB sodium)
        if(SODIUM_LIB)
            target_link_libraries(audio_call PRIVATE ${SODIUM_LIB})
        else()
            message(FATAL_ERROR "libsodium not found")
        endif()
    endif()

    # Поиск opus
    pkg_check_modules(OPUS opus)
    if(OPUS_FOUND)
        target_include_directories(audio_call PRIVATE ${OPUS_INCLUDE_DIRS})
        target_link_libraries(audio_call PRIVATE ${OPUS_LIBRARIES})
    else()
        find_library(OPUS_LIB opus)
        if(OPUS_LIB)
            target_link_libraries(audio_call PRIVATE ${OPUS_LIB})
        else()
            message(FATAL_ERROR "opus not found")
        endif()
    endif()

    # Поиск portaudio
    find_library(PORTAUDIO_LIB portaudio)
    if(PORTAUDIO_LIB)
        target_link_libraries(audio_call PRIVATE ${PORTAUDIO_LIB})
    else()
        message(FATAL_ERROR "portaudio not found")
    endif()
endif()

# Отладочная информация
message(STATUS "libsodium path: ${LIBSODIUM_ROOT}")
message(STATUS "opus path: ${OPUS_ROOT}")
message(STATUS "portaudio path: ${PORTAUDIO_ROOT}")