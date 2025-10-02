cmake_minimum_required(VERSION 3.16)
project(fear_gui)
set(CMAKE_CXX_STANDARD 17)

# Настройка путей сборки
set(CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/../build")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../../build/release")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Настройка статической линковки
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")  # Статическая линковка для MSVC
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)  # Отключаем PIC для статической линковки

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# Получаем путь к windeployqt (только для Windows)
if(WIN32)
    get_target_property(QMAKE_LOCATION Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_BIN_DIR "${QMAKE_LOCATION}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${QT_BIN_DIR}")
endif()

# Используем прямые слеши для Windows путей
set(LIBSODIUM_PATH "${CMAKE_SOURCE_DIR}/../../lib/libsodium-win64" CACHE PATH "Path to libsodium directory (should contain include/ and lib/ folders)")

if(LIBSODIUM_PATH)
    message(STATUS "Using libsodium from: ${LIBSODIUM_PATH}")
    
    # Проверяем существование директории
    if(NOT EXISTS ${LIBSODIUM_PATH})
        message(FATAL_ERROR "Libsodium directory not found: ${LIBSODIUM_PATH}")
    endif()
    
    # Include директории
    if(EXISTS ${LIBSODIUM_PATH}/include)
        set(LIBSODIUM_INCLUDE_DIRS ${LIBSODIUM_PATH}/include)
        message(STATUS "Found include directory: ${LIBSODIUM_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "Cannot find include directory in ${LIBSODIUM_PATH}")
    endif()
    
    # Проверяем наличие заголовочного файла
    if(NOT EXISTS ${LIBSODIUM_INCLUDE_DIRS}/sodium.h)
        message(FATAL_ERROR "sodium.h not found in ${LIBSODIUM_INCLUDE_DIRS}")
    endif()
    
    # Принудительно используем статическую библиотеку
    if(WIN32)
        # В первую очередь ищем статическую библиотеку libsodium.a
        if(EXISTS ${LIBSODIUM_PATH}/lib/libsodium.a)
            set(LIBSODIUM_LIBRARIES ${LIBSODIUM_PATH}/lib/libsodium.a)
            message(STATUS "Using static libsodium.a: ${LIBSODIUM_LIBRARIES}")
        # Затем ищем libsodium.lib (статическая для MSVC)
        elseif(EXISTS ${LIBSODIUM_PATH}/lib/libsodium.lib)
            set(LIBSODIUM_LIBRARIES ${LIBSODIUM_PATH}/lib/libsodium.lib)
            message(STATUS "Using static libsodium.lib: ${LIBSODIUM_LIBRARIES}")
        # Если статических нет, только тогда используем динамические
        elseif(EXISTS ${LIBSODIUM_PATH}/lib/libsodium.dll.a)
            set(LIBSODIUM_LIBRARIES ${LIBSODIUM_PATH}/lib/libsodium.dll.a)
            message(STATUS "WARNING: Using dynamic libsodium.dll.a (static not found): ${LIBSODIUM_LIBRARIES}")
        else()
            # Выводим список файлов в lib директории для отладки
            file(GLOB LIB_FILES "${LIBSODIUM_PATH}/lib/*")
            message(STATUS "Files in lib directory: ${LIB_FILES}")
            message(FATAL_ERROR "Cannot find libsodium library in ${LIBSODIUM_PATH}/lib/")
        endif()
    else()
        # Для Linux/Unix используем только статическую библиотеку
        if(EXISTS ${LIBSODIUM_PATH}/lib/libsodium.a)
            set(LIBSODIUM_LIBRARIES ${LIBSODIUM_PATH}/lib/libsodium.a)
            message(STATUS "Using static libsodium.a: ${LIBSODIUM_LIBRARIES}")
        else()
            message(FATAL_ERROR "Cannot find static libsodium.a in ${LIBSODIUM_PATH}/lib/")
        endif()
    endif()
    
else()
    message(FATAL_ERROR "Please set LIBSODIUM_PATH to the libsodium directory")
endif()

qt_standard_project_setup()

# Добавляем иконку в ресурсы Qt
qt_add_resources(RESOURCES_FILES
    "resources.qrc"
)

set(SOURCES 
    main.cpp 
    key_exchange.cpp
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${RESOURCES_FILES}
)

if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# Настройка статической линковки для Qt (если доступно)
if(QT_STATIC_BUILD)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(BUILD_SHARED_LIBS OFF)
endif()

target_link_libraries(fear_gui PRIVATE 
    Qt6::Widgets
    ${LIBSODIUM_LIBRARIES}
)

target_include_directories(fear_gui PRIVATE ${LIBSODIUM_INCLUDE_DIRS})

# Дополнительные флаги компиляции для статической линковки
if(WIN32)
    # Добавляем определение для Windows
    target_compile_definitions(fear_gui PRIVATE 
        -DNOMINMAX
        -DQT_STATIC_BUILD  # Если используется статический Qt
    )
    
    # Флаги для статической линковки
    if(MSVC)
        target_compile_options(fear_gui PRIVATE /W3 /MT$<$<CONFIG:Debug>:d>)
    else()
        # MinGW флаги для статической линковки
        target_compile_options(fear_gui PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
    
    # Для статической линковки убираем копирование DLL
    if(NOT LIBSODIUM_LIBRARIES MATCHES ".*\\.dll\\.a$")
        message(STATUS "Static linking - no DLL copy needed")
    endif()
else()
    # Linux/Unix флаги для статической линковки
    target_compile_options(fear_gui PRIVATE -static-libgcc -static-libstdc++)
endif()

# Дополнительно для Windows - создание .rc файла
if(WIN32)
    set(APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/logo.ico")
    if(EXISTS ${APP_ICON})
        file(WRITE "${CMAKE_BINARY_DIR}/app_icon.rc" "IDI_ICON1 ICON DISCARDABLE \"${APP_ICON}\"")
        target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_BINARY_DIR}/app_icon.rc")
        message(STATUS "Added app icon: ${APP_ICON}")
    else()
        message(WARNING "App icon not found: ${APP_ICON}")
    endif()
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    AUTORCC ON
)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR})
file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(MAKE_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

# Добавляем windeployqt после сборки (только для Windows)
if(WIN32 AND WINDEPLOYQT_EXECUTABLE)
    # Полный путь к исполняемому файлу
    set(TARGET_PATH "$<TARGET_FILE:${PROJECT_NAME}>")
    
    # Добавляем пользовательскую команду, которая выполняется после сборки
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        COMMENT "Running windeployqt to deploy Qt dependencies"
        VERBATIM
    )
    
    message(STATUS "windeployqt will run automatically after build")
elseif(WIN32)
    message(WARNING "windeployqt not found - Qt dependencies will not be deployed automatically")
else()
    message(STATUS "Skipping windeployqt - not needed on Linux/Unix")
endif()

message(STATUS "Libsodium configuration complete:")
message(STATUS "  Include dirs: ${LIBSODIUM_INCLUDE_DIRS}")
message(STATUS "  Libraries: ${LIBSODIUM_LIBRARIES}")
message(STATUS "  Linking: Static")