@echo off
setlocal EnableDelayedExpansion

REM =============================================================================
REM FEAR Project - Professional Build Script for Windows
REM =============================================================================
REM This script builds the entire FEAR project with a single command.
REM All output files will be placed in: build\bin\
REM
REM Usage:
REM   build.bat          - Build the project
REM   build.bat clean    - Clean build artifacts
REM   build.bat rebuild  - Clean and rebuild
REM =============================================================================

REM Enable ANSI color support for Windows 10+
for /f %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"

REM Project directories
set "PROJECT_ROOT=%~dp0"
set "BUILD_TEMP_DIR=%PROJECT_ROOT%.build-temp"
set "GUI_BUILD_DIR=%PROJECT_ROOT%gui\src\.build-temp"
set "OUTPUT_DIR=%PROJECT_ROOT%build"

REM Colors (using escape sequences for Windows 10+)
set "BLUE=%ESC%[94m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "RED=%ESC%[91m"
set "NC=%ESC%[0m"

echo.
echo ========================================
echo   FEAR Project Build System
echo ========================================
echo.

REM Handle command line arguments
set "COMMAND=%~1"
if "%COMMAND%"=="" set "COMMAND=build"

if /i "%COMMAND%"=="clean" (
    call :clean_build
    echo %GREEN%All build artifacts cleaned%NC%
    pause
    exit /b 0
)

if /i "%COMMAND%"=="rebuild" (
    call :clean_build
    set "COMMAND=build"
)

if /i not "%COMMAND%"=="build" (
    echo %RED%Unknown command: %COMMAND%%NC%
    echo Usage: build.bat [build^|clean^|rebuild]
    pause
    exit /b 1
)

REM =============================================================================
REM Check for required tools
REM =============================================================================

echo %YELLOW%Checking dependencies...%NC%

where cmake >nul 2>&1
if errorlevel 1 (
    echo %RED%CMake is not installed or not in PATH%NC%
    echo Please install CMake from https://cmake.org/download/
    pause
    exit /b 1
)

where gcc >nul 2>&1
if errorlevel 1 (
    echo %RED%GCC/MinGW is not installed or not in PATH%NC%
    echo Please install MinGW-w64 or add it to PATH
    pause
    exit /b 1
)

echo %GREEN%All dependencies found%NC%
echo.

REM Create output directories
if not exist "%OUTPUT_DIR%\bin" mkdir "%OUTPUT_DIR%\bin"
if not exist "%OUTPUT_DIR%\doc" mkdir "%OUTPUT_DIR%\doc"

REM =============================================================================
REM Build Main Project
REM =============================================================================

echo ========================================
echo   Building Main Project
echo ========================================
echo.

cd /d "%PROJECT_ROOT%"

REM Create temporary build directory
if not exist "%BUILD_TEMP_DIR%" mkdir "%BUILD_TEMP_DIR%"
cd /d "%BUILD_TEMP_DIR%"

echo %YELLOW%Configuring with CMake...%NC%
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 goto build_error

echo %YELLOW%Building...%NC%
cmake --build . --config Release -j %NUMBER_OF_PROCESSORS%
if errorlevel 1 goto build_error

echo %GREEN%Main project built successfully%NC%
echo.

REM =============================================================================
REM Build GUI Application
REM =============================================================================

echo ========================================
echo   Building GUI Application
echo ========================================
echo.

cd /d "%PROJECT_ROOT%gui\src"

REM Create temporary build directory
if not exist "%GUI_BUILD_DIR%" mkdir "%GUI_BUILD_DIR%"
cd /d "%GUI_BUILD_DIR%"

echo %YELLOW%Configuring GUI with CMake...%NC%
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 goto build_error

echo %YELLOW%Building GUI...%NC%
cmake --build . --config Release -j %NUMBER_OF_PROCESSORS%
if errorlevel 1 goto build_error

echo %GREEN%GUI built successfully%NC%
echo.

REM =============================================================================
REM Clean temporary files
REM =============================================================================

echo %YELLOW%Cleaning temporary build files...%NC%
cd /d "%PROJECT_ROOT%"
if exist "%BUILD_TEMP_DIR%" rmdir /s /q "%BUILD_TEMP_DIR%" 2>nul
if exist "%GUI_BUILD_DIR%" rmdir /s /q "%GUI_BUILD_DIR%" 2>nul

REM =============================================================================
REM Show Results
REM =============================================================================

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo All executables are located in: %OUTPUT_DIR%\bin\
echo.
echo Built applications:

if exist "%OUTPUT_DIR%\bin" (
    for %%f in ("%OUTPUT_DIR%\bin\*.exe") do (
        echo   * %%~nxf
    )
)

echo.
echo Documentation: %OUTPUT_DIR%\doc\
echo.

echo %GREEN%Build process completed successfully!%NC%
echo.
pause
exit /b 0

REM =============================================================================
REM Functions
REM =============================================================================

:clean_build
echo ========================================
echo   Cleaning Build Artifacts
echo ========================================
echo.

echo %YELLOW%Removing temporary build directories...%NC%
if exist "%BUILD_TEMP_DIR%" rmdir /s /q "%BUILD_TEMP_DIR%" 2>nul
if exist "%GUI_BUILD_DIR%" rmdir /s /q "%GUI_BUILD_DIR%" 2>nul

echo %GREEN%Clean completed%NC%
echo.
exit /b 0

:build_error
echo.
echo %RED%Build failed!%NC%
echo.
pause
exit /b 1
