cmake_minimum_required(VERSION 3.10)
project(key-exchange VERSION 2.0.0 LANGUAGES C)

# Настройка стандарта C
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Общие флаги компиляции
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Опция для статической линковки (по умолчанию включена)
option(STATIC_BUILD "Build with static linking" ON)

# Определение платформы
if(WIN32)
    set(EXECUTABLE_NAME "key-exchange")
    add_compile_definitions(_WIN32_WINNT=0x0600)

    # Настройка статической линковки для Windows
    if(STATIC_BUILD AND (MINGW OR CMAKE_C_COMPILER_ID MATCHES "GNU"))
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc")
    endif()
else()
    set(EXECUTABLE_NAME "key-exchange")
endif()

# Поиск libsodium
if(WIN32)
    # На Windows используем переменную LIBSODIUM_ROOT из родительского CMakeLists.txt
    if(DEFINED LIBSODIUM_ROOT)
        message(STATUS "Using LIBSODIUM_ROOT: ${LIBSODIUM_ROOT}")

        # Поиск заголовочных файлов
        find_path(SODIUM_INCLUDE_DIR sodium.h
            PATHS
                ${LIBSODIUM_ROOT}/include
                ${LIBSODIUM_ROOT}/x64/include
            NO_DEFAULT_PATH
        )

        # Поиск библиотеки
        find_library(SODIUM_LIBRARY
            NAMES libsodium.lib libsodium.a libsodium.dll.a sodium
            PATHS
                ${LIBSODIUM_ROOT}/lib
                ${LIBSODIUM_ROOT}/x64/lib
                ${LIBSODIUM_ROOT}/x64/Release/v143/static
                ${LIBSODIUM_ROOT}/x64/Release/v143/dynamic
            NO_DEFAULT_PATH
        )

        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
            set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
            message(STATUS "Found libsodium include: ${SODIUM_INCLUDE_DIR}")
            message(STATUS "Found libsodium library: ${SODIUM_LIBRARY}")
        endif()
    else()
        message(WARNING "LIBSODIUM_ROOT not set, trying to find libsodium manually")

        # Попытка найти в стандартных местах для Windows
        find_path(SODIUM_INCLUDE_DIR sodium.h
            PATHS
                ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/include
                ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/x64/include
                "C:/Program Files/libsodium/include"
        )

        find_library(SODIUM_LIBRARY
            NAMES libsodium.lib libsodium.a libsodium.dll.a sodium
            PATHS
                ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/lib
                ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/x64/lib
                ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/x64/Release/v143/static
                ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/x64/Release/v143/dynamic
                "C:/Program Files/libsodium/lib"
        )

        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
            set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
        endif()
    endif()
else()
    # На Linux/macOS используем pkg-config
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM libsodium)
    endif()

    # Если pkg-config не нашел libsodium, пробуем найти вручную
    if(NOT SODIUM_FOUND)
        find_path(SODIUM_INCLUDE_DIR sodium.h
            PATHS
                /usr/include
                /usr/local/include
                ${CMAKE_SOURCE_DIR}/external/libsodium/include
        )

        if(STATIC_BUILD)
            find_library(SODIUM_LIBRARY
                NAMES libsodium.a sodium
                PATHS
                    /usr/lib
                    /usr/local/lib
                    /usr/lib/x86_64-linux-gnu
                    ${CMAKE_SOURCE_DIR}/external/libsodium/lib
            )
        else()
            find_library(SODIUM_LIBRARY
                NAMES sodium
                PATHS
                    /usr/lib
                    /usr/local/lib
                    /usr/lib/x86_64-linux-gnu
                    ${CMAKE_SOURCE_DIR}/external/libsodium/lib
            )
        endif()

        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
            set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
        endif()
    endif()
endif()

if(NOT SODIUM_FOUND)
    message(FATAL_ERROR "libsodium not found! Please install libsodium development package.\n"
                        "Debian/Ubuntu: sudo apt-get install libsodium-dev\n"
                        "RHEL/CentOS: sudo yum install libsodium-devel\n"
                        "macOS: brew install libsodium\n"
                        "Windows: Download from https://download.libsodium.org/libsodium/releases/\n"
                        "  Place in ${CMAKE_SOURCE_DIR}/lib/libsodium-win64/")
endif()

# Исходные файлы
file(GLOB SOURCES "src/*.c")

# Создание исполняемого файла
add_executable(${PROJECT_NAME} ${SOURCES})

# Установка свойств цели
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME ${EXECUTABLE_NAME}
)

# Включение директорий
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Линковка библиотек
target_link_libraries(${PROJECT_NAME} PRIVATE ${SODIUM_LIBRARIES})

# Для Windows добавляем системные библиотеки
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 advapi32)

    # Копирование DLL в выходную директорию
    if(DEFINED LIBSODIUM_ROOT)
        # Поиск DLL файла
        file(GLOB SODIUM_DLL
            "${LIBSODIUM_ROOT}/bin/libsodium.dll"
            "${LIBSODIUM_ROOT}/x64/Release/v143/dynamic/libsodium.dll"
        )

        if(SODIUM_DLL)
            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${SODIUM_DLL}
                    $<TARGET_FILE_DIR:${PROJECT_NAME}>
                COMMENT "Copying libsodium.dll to output directory"
            )
            message(STATUS "Will copy libsodium.dll: ${SODIUM_DLL}")
        else()
            message(WARNING "libsodium.dll not found in ${LIBSODIUM_ROOT}/bin")
        endif()
    endif()
endif()

# Дополнительные флаги для статической сборки
if(STATIC_BUILD)
    if(UNIX AND NOT APPLE)
        # Для Linux статическая линковка
        target_link_options(${PROJECT_NAME} PRIVATE -static)
    endif()

    # Попытка найти статическую версию pthread для Linux
    if(UNIX AND NOT APPLE)
        set(THREADS_PREFER_PTHREAD_FLAG ON)
        find_package(Threads REQUIRED)
        target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)
    endif()
endif()

# Вывод информации о конфигурации
message(STATUS "key-exchange configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Static build: ${STATIC_BUILD}")
message(STATUS "  libsodium include: ${SODIUM_INCLUDE_DIRS}")
message(STATUS "  libsodium library: ${SODIUM_LIBRARIES}")

# Дополнительная цель для очистки
add_custom_target(clean-key-exchange
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMENT "Cleaning key-exchange build artifacts"
)