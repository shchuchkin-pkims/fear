cmake_minimum_required(VERSION 3.12)
project(updater C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Общие флаги компиляции
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Поиск исходных файлов
file(GLOB SOURCES "src/*.c")

# Создание исполняемого файла
add_executable(updater ${SOURCES})

# Платформо-зависимые настройки
if(WIN32)
    # Получаем путь из родительского CMake или используем по умолчанию
    if(NOT DEFINED CURL_ROOT)
        set(CURL_ROOT "${CMAKE_SOURCE_DIR}/../lib/curl-8.15.0_5-win64-mingw")
    endif()

    set(CURL_DIR "${CURL_ROOT}")
    set(CURL_INCLUDE_DIR "${CURL_DIR}/include")
    set(CURL_LIBRARY_DIR "${CURL_DIR}/lib")

    # Проверка существования директорий
    if(NOT EXISTS "${CURL_DIR}")
        message(FATAL_ERROR "Curl directory not found: ${CURL_DIR}")
    endif()

    if(NOT EXISTS "${CURL_LIBRARY_DIR}")
        message(FATAL_ERROR "Curl lib directory not found: ${CURL_LIBRARY_DIR}")
    endif()

    # Настройка include директорий и линковка для Windows
    target_include_directories(updater PRIVATE "${CURL_INCLUDE_DIR}")
    target_link_libraries(updater PRIVATE
        "${CURL_LIBRARY_DIR}/libcurl.dll.a"
        ws2_32
        bcrypt
        crypt32
    )

    message(STATUS "CURL_DIR: ${CURL_DIR}")
else()
    # Для Linux и macOS - используем системную libcurl
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CURL REQUIRED libcurl)

    target_include_directories(updater PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(updater PRIVATE ${CURL_LIBRARIES})

    message(STATUS "Using system libcurl: ${CURL_VERSION}")
endif()