cmake_minimum_required(VERSION 3.16)
project(fear_gui)
set(CMAKE_CXX_STANDARD 17)

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
)

# НЕ добавляйте .ico файл напрямую в add_executable!
# Он должен быть только в ресурсах (.qrc файле)

target_link_libraries(fear_gui PRIVATE Qt6::Widgets)

# Дополнительно для Windows - создание .rc файла
if(WIN32)
    set(APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/logo.ico")

    # Создаем файл app_icon.rc.in если его нет
    file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/app_icon.rc.in" "IDI_ICON1 ICON DISCARDABLE \"@APP_ICON@\"")

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/app_icon.rc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/app_icon.rc"
    )

    # Добавляем ресурсный файл к исполняемому файлу
    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/app_icon.rc")
endif()
