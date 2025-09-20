cmake_minimum_required(VERSION 3.10)
project(key-exchange VERSION 1.0.0 LANGUAGES C)

# Настройка стандарта C
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Общие флаги компиляции
add_compile_options(-O2 -Wall -Wextra -pedantic)

# Определение платформы
if(WIN32)
    set(EXECUTABLE_NAME "key-exchange")
    add_compile_definitions(_WIN32_WINNT=0x0600)
    
    # Настройка статической линковки для Windows
    if(MINGW OR CMAKE_C_COMPILER_ID MATCHES "GNU")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()
else()
    set(EXECUTABLE_NAME "key-exchange")
    # Поиск математической библиотеки для Linux
    find_library(MATH_LIBRARY m)
    if(MATH_LIBRARY)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lm")
    endif()
endif()

# Исходные файлы
file(GLOB SOURCES "src/*.c")

# Создание исполняемого файла
add_executable(${PROJECT_NAME} ${SOURCES})

# Установка свойств цели
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME ${EXECUTABLE_NAME}
    VERSION ${PROJECT_VERSION}
)

# Включение директорий
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Дополнительная цель для очистки
add_custom_target(clean-key-exchange
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMENT "Cleaning key-exchange build artifacts"
)