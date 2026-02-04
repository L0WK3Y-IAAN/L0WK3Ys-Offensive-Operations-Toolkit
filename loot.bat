@echo off
REM L0WK3Y's Offensive Operations Toolkit (LOOT) Launcher
REM This batch file can be added to your PATH to launch LOOT from anywhere

setlocal enabledelayedexpansion

REM Try to find the project directory
set "LOOT_DIR="

REM Method 1: Check if LOOT_HOME environment variable is set
if defined LOOT_HOME (
    set "LOOT_DIR=!LOOT_HOME!"
    goto :found_dir
)

REM Method 2: Check if this batch file is in the project root
set "BAT_DIR=%~dp0"
if exist "!BAT_DIR!main.py" (
    set "LOOT_DIR=!BAT_DIR!"
    goto :found_dir
)

REM Method 3: Try common installation locations
if exist "C:\Users\%USERNAME%\Documents\Github\L0WK3Ys-Offensive-Operations-Toolkit\main.py" (
    set "LOOT_DIR=C:\Users\%USERNAME%\Documents\Github\L0WK3Ys-Offensive-Operations-Toolkit\"
    goto :found_dir
)

if exist "%USERPROFILE%\Documents\Github\L0WK3Ys-Offensive-Operations-Toolkit\main.py" (
    set "LOOT_DIR=%USERPROFILE%\Documents\Github\L0WK3Ys-Offensive-Operations-Toolkit\"
    goto :found_dir
)

REM Method 4: Search in current directory and parent directories
set "SEARCH_DIR=%~dp0"
:search_up
if exist "!SEARCH_DIR!main.py" (
    set "LOOT_DIR=!SEARCH_DIR!"
    goto :found_dir
)
set "PARENT_DIR=!SEARCH_DIR!..\"
if "!PARENT_DIR!"=="!SEARCH_DIR!" goto :not_found
set "SEARCH_DIR=!PARENT_DIR!"
goto :search_up

:not_found
echo.
echo [ERROR] Could not find LOOT project directory.
echo.
echo Please do one of the following:
echo   1. Set the LOOT_HOME environment variable to point to the project directory
echo   2. Place this batch file in the project root directory
echo   3. Run this batch file from the project directory
echo.
echo Example: set LOOT_HOME=C:\Users\YourName\Documents\Github\L0WK3Ys-Offensive-Operations-Toolkit
echo.
pause
exit /b 1

:found_dir
REM Remove trailing backslash if present
if "!LOOT_DIR:~-1!"=="\" set "LOOT_DIR=!LOOT_DIR:~0,-1!"

REM Change to project directory
cd /d "!LOOT_DIR!"
if errorlevel 1 (
    echo [ERROR] Could not change to directory: !LOOT_DIR!
    pause
    exit /b 1
)

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and ensure it's in your PATH.
    pause
    exit /b 1
)

REM Check if main.py exists
if not exist "main.py" (
    echo [ERROR] main.py not found in: !LOOT_DIR!
    pause
    exit /b 1
)

REM Try to find and activate virtual environment
set "VENV_ACTIVATED=0"
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
    set "VENV_ACTIVATED=1"
    goto :venv_ready
)
if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
    set "VENV_ACTIVATED=1"
    goto :venv_ready
)
if exist "env\Scripts\activate.bat" (
    call "env\Scripts\activate.bat"
    set "VENV_ACTIVATED=1"
    goto :venv_ready
)

REM If no venv found, warn but continue
echo [WARNING] No virtual environment found. Using system Python.
echo          Consider creating a venv: python -m venv .venv
echo.

:venv_ready
REM Run the LOOT launcher
python main.py

REM Preserve exit code
set "EXIT_CODE=!ERRORLEVEL!"
if !EXIT_CODE! neq 0 (
    echo.
    echo [INFO] LOOT exited with code !EXIT_CODE!
)

endlocal
exit /b %EXIT_CODE%
