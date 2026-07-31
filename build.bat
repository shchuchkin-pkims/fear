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

REM The old check looked for cmake and gcc, announced "All dependencies found"
REM and then let CMake fail much later on a missing library. It also never
REM looked at lib\, which a fresh clone does NOT have: lib\ is in .gitignore,
REM so the prebuilt Windows libraries are not part of the repository. Collect
REM everything that is missing and report it in one pass.

set "DEPS_OK=1"

where cmake >nul 2>&1
if errorlevel 1 (
    echo   command: cmake            - https://cmake.org/download/
    set "DEPS_OK=0"
)

where gcc >nul 2>&1
if errorlevel 1 (
    echo   command: gcc ^(MinGW-w64^)  - https://winlibs.com/ or MSYS2
    set "DEPS_OK=0"
)

REM Qt6 is needed for fear_gui. windeployqt ships with every Qt install and is
REM what the packaging step below calls, so its absence is the useful signal.
where windeployqt >nul 2>&1
if errorlevel 1 (
    where qmake6 >nul 2>&1
    if errorlevel 1 (
        echo   toolkit: Qt6             - https://www.qt.io/download, add its bin\ to PATH
        set "DEPS_OK=0"
    )
)

REM Library directories, with the exact names CMakeLists.txt expects. Renaming
REM any of these breaks the build with a confusing CMake error instead of this
REM message, so they are spelled out rather than globbed.
if not exist "%PROJECT_ROOT%\lib\libsodium-win64\include\sodium.h" (
    echo   library: lib\libsodium-win64             - libsodium
    set "DEPS_OK=0"
)
if not exist "%PROJECT_ROOT%\lib\curl-8.15.0_5-win64-mingw" (
    echo   library: lib\curl-8.15.0_5-win64-mingw   - libcurl ^(updater^)
    set "DEPS_OK=0"
)
if not exist "%PROJECT_ROOT%\lib\opus-1.5.2" (
    echo   library: lib\opus-1.5.2                  - Opus ^(audio calls^)
    set "DEPS_OK=0"
)
if not exist "%PROJECT_ROOT%\lib\portaudio" (
    echo   library: lib\portaudio                   - PortAudio ^(audio I/O^)
    set "DEPS_OK=0"
)
if not exist "%PROJECT_ROOT%\lib\ffmpeg-win64" (
    echo   library: lib\ffmpeg-win64                - FFmpeg ^(video calls^)
    set "DEPS_OK=0"
)
if not exist "%PROJECT_ROOT%\lib\SDL3-win64" (
    echo   library: lib\SDL3-win64                  - SDL3 ^(video display^)
    set "DEPS_OK=0"
)

if "%DEPS_OK%"=="0" (
    echo.
    echo %RED%Missing dependencies - the build would fail later, stopping here.%NC%
    echo See doc\BUILD.md for exactly where each library goes and where to get it.
    echo.
    echo Note: lib\ is not part of the git repository, so a fresh clone always
    echo needs the libraries above to be placed there once.
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
REM Deploy Qt Dependencies
REM =============================================================================

echo ========================================
echo   Deploying Qt Dependencies
echo ========================================
echo.

REM Check if fear_gui.exe exists
if not exist "%OUTPUT_DIR%\fear_gui.exe" (
    echo %RED%Error: fear_gui.exe not found in %OUTPUT_DIR%%NC%
    goto build_error
)

echo %YELLOW%Searching for windeployqt...%NC%

REM Try to find windeployqt in PATH
where windeployqt >nul 2>&1
if errorlevel 1 (
    REM Try to find Qt installation
    echo %YELLOW%windeployqt not in PATH, searching Qt installation...%NC%

    REM Common Qt installation paths
    set "QT_PATHS=C:\Qt\6.8.0\mingw_64\bin;C:\Qt\6.7.0\mingw_64\bin;C:\Qt\6.6.0\mingw_64\bin;C:\Qt\6.5.0\mingw_64\bin;C:\Qt\6.4.0\mingw_64\bin"

    set "WINDEPLOYQT_FOUND="
    for %%p in ("%QT_PATHS:;=" "%") do (
        if exist "%%~p\windeployqt.exe" (
            set "WINDEPLOYQT=%%~p\windeployqt.exe"
            set "WINDEPLOYQT_FOUND=1"
            echo %GREEN%Found windeployqt at: %%~p%NC%
            goto :found_windeployqt
        )
    )

    if not defined WINDEPLOYQT_FOUND (
        echo %RED%WARNING: windeployqt not found!%NC%
        echo Qt DLL files will NOT be deployed automatically.
        echo.
        echo To fix this issue:
        echo 1. Add Qt bin directory to PATH, or
        echo 2. Run windeployqt manually: windeployqt %OUTPUT_DIR%\fear_gui.exe
        echo.
        echo %YELLOW%GUI may not work on systems without Qt installed.%NC%
        echo.
        goto skip_windeployqt
    )
) else (
    set "WINDEPLOYQT=windeployqt"
)

:found_windeployqt
echo %YELLOW%Running windeployqt to deploy Qt libraries...%NC%
cd /d "%OUTPUT_DIR%"
"%WINDEPLOYQT%" fear_gui.exe --release --no-translations
if errorlevel 1 (
    echo %RED%Warning: windeployqt completed with errors%NC%
    echo %YELLOW%GUI may not work properly%NC%
) else (
    echo %GREEN%Qt dependencies deployed successfully%NC%
)
echo.

:skip_windeployqt

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
