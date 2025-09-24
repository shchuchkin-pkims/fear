cmake_minimum_required(VERSION 3.12)
project(fear-project VERSION 1.0.0 LANGUAGES C)

# Настройка стандарта C для всех субпроектов
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Общие флаги компиляции
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Определение платформы
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0600)
    
    # Настройка статической линковки для MinGW
    if(MINGW OR CMAKE_C_COMPILER_ID MATCHES "GNU")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()
endif()

# Установка путей для библиотек в папке lib
set(LIBS_DIR "${CMAKE_SOURCE_DIR}/lib")
set(LIBSODIUM_ROOT "${LIBS_DIR}/libsodium-win64")
set(CURL_ROOT "${LIBS_DIR}/curl-8.15.0_5-win64-mingw")
set(OPUS_ROOT "${LIBS_DIR}/opus-1.5.2")
set(PORTAUDIO_ROOT "${LIBS_DIR}/portaudio")

# Передача путей в субмодули
set(LIBS_DIR "${LIBS_DIR}" CACHE PATH "Path to libraries directory")
set(LIBSODIUM_ROOT "${LIBSODIUM_ROOT}" CACHE PATH "Path to libsodium")
set(CURL_ROOT "${CURL_ROOT}" CACHE PATH "Path to curl")
set(OPUS_ROOT "${OPUS_ROOT}" CACHE PATH "Path to opus")
set(PORTAUDIO_ROOT "${PORTAUDIO_ROOT}" CACHE PATH "Path to portaudio")

# Проверка существования библиотечных директорий
if(WIN32)
    if(NOT EXISTS "${LIBSODIUM_ROOT}")
        message(WARNING "libsodium not found at: ${LIBSODIUM_ROOT}")
        message(STATUS "Please download libsodium and place it in lib/ directory")
    else()
        message(STATUS "Found libsodium at: ${LIBSODIUM_ROOT}")
    endif()
    
    if(NOT EXISTS "${CURL_ROOT}")
        message(WARNING "curl not found at: ${CURL_ROOT}")
        message(STATUS "Please download curl and place it in lib/ directory")
    else()
        message(STATUS "Found curl at: ${CURL_ROOT}")
    endif()
    
    if(NOT EXISTS "${OPUS_ROOT}")
        message(WARNING "opus not found at: ${OPUS_ROOT}")
        message(STATUS "Please download opus and place it in lib/ directory")
    else()
        message(STATUS "Found opus at: ${OPUS_ROOT}")
    endif()
    
    if(NOT EXISTS "${PORTAUDIO_ROOT}")
        message(WARNING "portaudio not found at: ${PORTAUDIO_ROOT}")
        message(STATUS "Please download portaudio and place it in lib/ directory")
    else()
        message(STATUS "Found portaudio at: ${PORTAUDIO_ROOT}")
    endif()
endif()

# Включение субмодулей
add_subdirectory(client-console)
add_subdirectory(key-exchange)
add_subdirectory(updater)
add_subdirectory(audio_call)

# Создание пользовательских целей для удобства
add_custom_target(build-all
    DEPENDS fear key-exchange updater audio_call
    COMMENT "Building all executables: fear.exe, key-exchange.exe, updater.exe, audio_call.exe"
)

add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMENT "Cleaning all build artifacts"
)

# Установка выходных файлов в корневую build директорию
set_target_properties(fear PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(key-exchange PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(updater PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(audio_call PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Информация о проекте
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Libraries directory: ${LIBS_DIR}")
message(STATUS "libsodium path: ${LIBSODIUM_ROOT}")
message(STATUS "curl path: ${CURL_ROOT}")
message(STATUS "opus path: ${OPUS_ROOT}")
message(STATUS "portaudio path: ${PORTAUDIO_ROOT}")

# Дополнительная цель для создания lib директории
add_custom_target(create-lib-dir
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBS_DIR}
    COMMENT "Creating lib directory for external libraries"
)

# Цель для показа информации о библиотеках
add_custom_target(lib-info
    COMMAND ${CMAKE_COMMAND} -E echo "Library paths:"
    COMMAND ${CMAKE_COMMAND} -E echo "  libsodium: ${LIBSODIUM_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E echo "  curl: ${CURL_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E echo "  opus: ${OPUS_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E echo "  portaudio: ${PORTAUDIO_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E echo "Download links:"
    COMMAND ${CMAKE_COMMAND} -E echo "  libsodium: https://download.libsodium.org/libsodium/releases/"
    COMMAND ${CMAKE_COMMAND} -E echo "  curl: https://curl.se/windows/"
    COMMAND ${CMAKE_COMMAND} -E echo "  opus: https://opus-codec.org/downloads/"
    COMMAND ${CMAKE_COMMAND} -E echo "  portaudio: http://www.portaudio.com/download.html"
    COMMENT "Showing library information and download links"
)

# Автоматическое создание структуры lib директории
if(WIN32 AND NOT EXISTS "${LIBS_DIR}")
    message(STATUS "Creating lib directory structure...")
    file(MAKE_DIRECTORY "${LIBS_DIR}")
    
    # Создание README с инструкциями
    file(WRITE "${LIBS_DIR}/README.txt"
        "Place external libraries here:\n"
        "1. Download curl from: https://curl.se/windows/\n"
        "   Extract to: curl-8.15.0_5-win64-mingw/\n"
        "2. Download libsodium from: https://download.libsodium.org/libsodium/releases/\n"
        "   Extract to: libsodium-win64/\n"
        "3. Download opus from: https://opus-codec.org/downloads/\n"
        "   Extract to: opus-1.5.2/\n"
        "4. Download portaudio from: http://www.portaudio.com/download.html\n"
        "   Extract to: portaudio/\n"
        "\n"
        "Required structure:\n"
        "lib/\n"
        "├── curl-8.15.0_5-win64-mingw/\n"
        "│   ├── include/curl/curl.h\n"
        "│   └── lib/libcurl.dll.a\n"
        "├── libsodium-win64/\n"
        "│   ├── include/sodium.h\n"
        "│   └── lib/libsodium.dll.a\n"
        "├── opus-1.5.2/\n"
        "│   ├── include/opus.h\n"
        "│   └── build/libopus.a\n"
        "└── portaudio/\n"
        "    ├── include/portaudio.h\n"
        "    └── build/libportaudio.a\n"
    )
endif()