cmake_minimum_required(VERSION 3.16)

# Утилита администрирования ретранслятора. Собирается только когда есть Qt6:
# сервер прекрасно работает и без неё, а на машине, где он развёрнут, Qt может
# не быть вовсе.
# Корневой проект объявлен как C-only, а Qt6 при поиске компилирует пробы на
# C++. Включаем язык здесь, а не в корне: серверу и консольному клиенту
# компилятор C++ не нужен, и требовать его ради утилиты было бы лишним.
enable_language(CXX)

find_package(Qt6 QUIET COMPONENTS Widgets Sql)

if(NOT Qt6_FOUND)
    message(STATUS "Qt6 not found - skipping the admin utility")
    return()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fear_admin
    src/main.cpp
    src/adminwindow.cpp
    src/serverdb.cpp
    # Отпечаток ключа считается той же функцией, что и у клиентов: своя копия
    # той же формулы однажды разъедется, а отпечаток - то, что люди сверяют
    # голосом.
    ${CMAKE_SOURCE_DIR}/identity/identity.c
    ${CMAKE_SOURCE_DIR}/identity/identity_at_rest.c
)

target_include_directories(fear_admin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/identity
)

target_link_libraries(fear_admin PRIVATE Qt6::Widgets Qt6::Sql fear_secret_store)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(ADMIN_SODIUM libsodium)
endif()
if(ADMIN_SODIUM_FOUND)
    target_include_directories(fear_admin PRIVATE ${ADMIN_SODIUM_INCLUDE_DIRS})
    target_link_libraries(fear_admin PRIVATE ${ADMIN_SODIUM_LIBRARIES})
else()
    find_library(ADMIN_SODIUM_LIB sodium REQUIRED)
    target_link_libraries(fear_admin PRIVATE ${ADMIN_SODIUM_LIB})
endif()

set_target_properties(fear_admin PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
