@echo off
REM Script to create a release ZIP archive for F.E.A.R. project (Windows)
REM Usage: pack_release.bat [version]
REM Example: pack_release.bat 0.3.0

setlocal enabledelayedexpansion

REM Get version from argument or use "latest"
set VERSION=%1
if "%VERSION%"=="" set VERSION=latest

REM Detect architecture
set ARCH=x86_64
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set ARCH=arm64
if "%PROCESSOR_ARCHITECTURE%"=="x86" set ARCH=x86

set OS=windows
set OUTPUT_NAME=fear-%OS%-%ARCH%.zip

echo =========================================
echo   F.E.A.R. Release Packager
echo =========================================
echo Version: %VERSION%
echo Platform: %OS%-%ARCH%
echo Output: %OUTPUT_NAME%
echo.

REM Check if build directory exists
if not exist "build\" (
    echo Error: build\ directory not found!
    echo Please run build.bat first to build the project.
    pause
    exit /b 1
)

REM Check if PowerShell is available
where powershell >nul 2>&1
if errorlevel 1 (
    echo Error: PowerShell not found!
    echo PowerShell is required for creating ZIP archives.
    pause
    exit /b 1
)

REM Create temporary directory for packaging
set TEMP_DIR=%TEMP%\fear_release_%RANDOM%
mkdir "%TEMP_DIR%"

echo ^-^> Preparing files...

REM Copy all files from build directory
echo   * Copying all files from build directory...
xcopy /E /I /Q "build\*" "%TEMP_DIR%\" >nul 2>&1

REM Copy only manual.pdf from documentation
if exist "doc\manual.pdf" (
    mkdir "%TEMP_DIR%\doc"
    copy "doc\manual.pdf" "%TEMP_DIR%\doc\" >nul 2>&1
    echo   * manual.pdf included
)

REM Create the ZIP archive using PowerShell
echo.
echo ^-^> Creating archive...

powershell -Command "Compress-Archive -Path '%TEMP_DIR%\*' -DestinationPath '%CD%\%OUTPUT_NAME%' -Force"

if errorlevel 1 (
    echo Error: Failed to create archive
    rmdir /S /Q "%TEMP_DIR%"
    pause
    exit /b 1
)

REM Cleanup temporary directory
rmdir /S /Q "%TEMP_DIR%"

REM Get file size
for %%A in ("%OUTPUT_NAME%") do set FILE_SIZE=%%~zA
set /A FILE_SIZE_MB=%FILE_SIZE% / 1048576

echo.
echo =========================================
echo   * Release package created!
echo =========================================
echo File: %OUTPUT_NAME%
echo Size: %FILE_SIZE_MB% MB
echo.
echo Next steps:
echo 1. Test the archive:
echo    powershell -Command "Expand-Archive -Path %OUTPUT_NAME% -DestinationPath test_extract -Force"
echo.
echo 2. Upload to GitHub Release:
echo    - Go to https://github.com/shchuchkin-pkims/fear/releases/new
echo    - Create tag: v%VERSION%
echo    - Upload: %OUTPUT_NAME%
echo.

pause
