cmake_minimum_required(VERSION 3.16)
project(fear_gui)
set(CMAKE_CXX_STANDARD 17)

# Настройка путей сборки - исправленная версия
set(CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/../build")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

# Добавляем иконку в ресурсы Qt
qt_add_resources(RESOURCES_FILES
    "resources.qrc"
)

# Включаем ресурсы в сборку
set(SOURCES main.cpp)

# Правильное создание исполняемого файла
add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${RESOURCES_FILES}
    dh.c dh.h
)

# Указываем, что это графическое приложение (без консоли)
if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
endif()


# НЕ добавляйте .ico файл напрямую в add_executable!
# Он должен быть только в ресурсах (.qrc файле)

target_link_libraries(fear_gui PRIVATE Qt6::Widgets)

# Дополнительно для Windows - создание .rc файла
if(WIN32)
    set(APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/logo.ico")

    # Создаем .rc файл напрямую без configure_file
    file(WRITE "${CMAKE_BINARY_DIR}/app_icon.rc" "IDI_ICON1 ICON DISCARDABLE \"${APP_ICON}\"")

    # Добавляем ресурсный файл к исполняемому файлу
    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_BINARY_DIR}/app_icon.rc")
endif()

# Дополнительные настройки для Qt
set_target_properties(${PROJECT_NAME} PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    AUTORCC ON
)

# Создаем необходимые папки
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR})
file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(MAKE_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
