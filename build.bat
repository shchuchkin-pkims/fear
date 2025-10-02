@echo off
setlocal EnableDelayedExpansion

echo ========================================
echo      FEAR Project Build Script
echo ========================================

REM Автоматическая очистка
echo Cleaning previous builds...
if exist "gui\src\build" rmdir /s /q "gui\src\build"
if exist "build" rmdir /s /q "build"
echo Clean completed.
echo.

echo Building FEAR Project...

REM Сборка GUI с Qt MingW
echo Step 1: Building GUI...
cd /d "%~dp0gui\src"
if not exist "build" mkdir build
cd build

set "PATH=C:\Qt\Tools\mingw1120_64\bin;%PATH%"
cmake -G "MinGW Makefiles" ..
if errorlevel 1 goto error
cmake --build .
if errorlevel 1 goto error

REM Сборка основного проекта с системным MingW
echo Step 2: Building main project...
cd /d "%~dp0"
if not exist "build" mkdir build
cd build

set "PATH=C:\mingw64\bin;%PATH%"
cmake -G "MinGW Makefiles" ..
if errorlevel 1 goto error
cmake --build .
if errorlevel 1 goto error

echo Build completed successfully!
pause
exit /b 0

:error
echo Build failed!
pause
exit /b 1