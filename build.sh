#!/bin/bash

echo "========================================"
echo "      FEAR Project Build Script"
echo "========================================"

# Проверка наличия необходимых утилит
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is not installed. Please install it first."
        exit 1
    fi
}

echo "Checking dependencies..."
check_dependency cmake
check_dependency gcc
check_dependency g++
echo "All dependencies found."
echo ""

# Автоматическая очистка
echo "Cleaning previous builds..."
rm -rf "gui/src/build"
rm -rf "build"
echo "Clean completed."
echo ""

echo "Building FEAR Project..."

# Функция для сборки с обработкой ошибок
build_project() {
    local project_dir="$1"
    local project_name="$2"
    
    echo "Building $project_name..."
    cd "$project_dir" || exit 1
    
    mkdir -p build
    cd build || exit 1
    
    if cmake ..; then
        if cmake --build .; then
            echo "$project_name build completed successfully!"
            return 0
        else
            echo "Error: $project_name build failed!"
            return 1
        fi
    else
        echo "Error: $project_name configuration failed!"
        return 1
    fi
}

# Сборка GUI
if ! build_project "gui/src" "GUI"; then
    exit 1
fi

echo ""

# Сборка основного проекта
if ! build_project "." "main project"; then
    exit 1
fi

echo ""
echo "========================================"
echo "      Build completed successfully!"
echo "========================================"
echo ""
echo "Output files:"
echo "- GUI: $(pwd)/../gui/src/build/fear-gui"
echo "- Main: $(pwd)/release/bin/*"
echo ""