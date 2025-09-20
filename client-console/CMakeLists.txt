cmake_minimum_required(VERSION 3.12)
project(fear VERSION 1.0.0 LANGUAGES C)

# Настройка стандарта C
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Общие флаги компиляции
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Определение платформы
if(WIN32)
    set(TARGET_NAME "fear")
    add_compile_definitions(_WIN32_WINNT=0x0600)
else()
    set(TARGET_NAME "fear")
endif()

# Директории с исходными файлами
set(SRC_DIR src)
set(INCLUDE_DIR include)

# Исходные файлы
file(GLOB SOURCES "${SRC_DIR}/*.c")

# Создание исполняемого файла
add_executable(${TARGET_NAME} ${SOURCES})

# Включение директорий
target_include_directories(${TARGET_NAME} PRIVATE ${INCLUDE_DIR})

# Настройка линковки libsodium
if(WIN32)
    # Получаем путь из родительского CMake или используем по умолчанию
    if(NOT DEFINED LIBSODIUM_ROOT)
        set(LIBSODIUM_ROOT "${CMAKE_SOURCE_DIR}/libsodium-win64")
    endif()
    
    # Проверяем несколько возможных путей
    set(SODIUM_PATHS
        "${LIBSODIUM_ROOT}"
        "${CMAKE_SOURCE_DIR}/../lib/libsodium-win64"
        "${CMAKE_SOURCE_DIR}/libsodium-win64"
        "C:/libsodium-win64" 
    )
    
    # Поиск директории libsodium
    foreach(SODIUM_PATH ${SODIUM_PATHS})
        if(EXISTS "${SODIUM_PATH}/include/sodium.h")
            set(FOUND_SODIUM_PATH ${SODIUM_PATH})
            break()
        endif()
    endforeach()
    
    if(FOUND_SODIUM_PATH)
        message(STATUS "Found libsodium at: ${FOUND_SODIUM_PATH}")
        target_include_directories(${TARGET_NAME} PRIVATE ${FOUND_SODIUM_PATH}/include)
        
        # Поиск библиотеки
        if(EXISTS "${FOUND_SODIUM_PATH}/lib/libsodium.a")
            target_link_libraries(${TARGET_NAME} ${FOUND_SODIUM_PATH}/lib/libsodium.a ws2_32)
        elseif(EXISTS "${FOUND_SODIUM_PATH}/lib/libsodium.lib")
            target_link_libraries(${TARGET_NAME} ${FOUND_SODIUM_PATH}/lib/libsodium.lib ws2_32)
        elseif(EXISTS "${FOUND_SODIUM_PATH}/lib/libsodium.dll.a")
            target_link_libraries(${TARGET_NAME} ${FOUND_SODIUM_PATH}/lib/libsodium.dll.a ws2_32)
        else()
            message(FATAL_ERROR "libsodium library not found in ${FOUND_SODIUM_PATH}/lib/")
        endif()
    else()
        message(FATAL_ERROR "libsodium not found. Please install libsodium for Windows and set LIBSODIUM_ROOT")
    endif()
else()
    # Поиск libsodium на Linux
    find_package(PkgConfig)
    pkg_check_modules(LIBSODIUM libsodium)
    if(LIBSODIUM_FOUND)
        target_include_directories(${TARGET_NAME} PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
        target_link_libraries(${TARGET_NAME} ${LIBSODIUM_LIBRARIES})
    else()
        # Альтернативный поиск
        find_library(SODIUM_LIB sodium)
        find_path(SODIUM_INCLUDE_DIR sodium.h PATH_SUFFIXES sodium)
        if(SODIUM_LIB AND SODIUM_INCLUDE_DIR)
            target_include_directories(${TARGET_NAME} PRIVATE ${SODIUM_INCLUDE_DIR})
            target_link_libraries(${TARGET_NAME} ${SODIUM_LIB})
        else()
            message(FATAL_ERROR "libsodium is required but not found. Install with: sudo apt-get install libsodium-dev")
        endif()
    endif()
endif()

# Установка свойств цели
set_target_properties(${TARGET_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
)