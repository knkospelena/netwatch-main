@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

:: =============================================================================
::  NetWatch - Universal Auto-Setup & Launch Script for Windows
::  Supports: Windows 10/11, x86_64, ARM64 (Surface Pro X, etc.)
::  Usage: Double-click run.bat  OR  run it from CMD/PowerShell as Administrator
:: =============================================================================

title NetWatch - Auto Setup

echo.
echo [96m
echo  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
echo  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
echo  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
echo  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
echo  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
echo  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
echo [0m
echo       Network Traffic Monitoring ^& Detection ^| Auto-Setup v2.0 (Windows)
echo ========================================================================
echo.

:: ── Change to script directory ───────────────────────────────────────────────
cd /d "%~dp0"

:: ── Check Admin Privileges ────────────────────────────────────────────────────
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [!] NetWatch requires Administrator privileges for packet sniffing.
    echo [*] Re-launching as Administrator...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
echo [+] Running with Administrator privileges.

:: ── Detect Architecture ───────────────────────────────────────────────────────
echo [*] Detecting system architecture...
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    echo [+] Architecture: ARM64 (Windows on ARM)
) else if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    echo [+] Architecture: x86_64 (64-bit)
) else (
    echo [+] Architecture: %PROCESSOR_ARCHITECTURE%
)

:: ── Check for Python ─────────────────────────────────────────────────────────
echo.
echo [*] Checking for Python 3.10+...

set PYTHON_CMD=
for %%P in (python3 python py) do (
    %%P --version >nul 2>&1
    if !errorlevel!==0 (
        for /f "tokens=2" %%V in ('%%P --version 2^>^&1') do (
            for /f "tokens=1,2 delims=." %%A in ("%%V") do (
                if %%A GEQ 3 (
                    if %%B GEQ 10 (
                        set PYTHON_CMD=%%P
                        echo [+] Found Python %%V at: %%P
                        goto :python_found
                    )
                )
            )
        )
    )
)

:: Python not found — install via winget
echo [!] Python 3.10+ not found. Attempting to install via winget...
winget install --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
if %errorlevel% NEQ 0 (
    echo [!] winget install failed. Trying direct download...
    :: Download Python installer
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\python_installer.exe'"
    "%TEMP%\python_installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    del "%TEMP%\python_installer.exe"
    echo [+] Python installed. Refreshing PATH...
    :: Refresh PATH
    for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable(\"PATH\",\"Machine\")"') do set PATH=%%i;%PATH%
)

:: Try again
set PYTHON_CMD=python
python --version >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [ERROR] Python installation failed or PATH not refreshed.
    echo         Please install Python 3.10+ from https://python.org/downloads/
    echo         Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

:python_found

:: ── Install Npcap (Windows packet capture driver) ────────────────────────────
echo.
echo [*] Checking for Npcap (required for scapy packet sniffing on Windows)...

:: Check if Npcap is installed
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if %errorlevel% EQU 0 (
    echo [+] Npcap is already installed.
) else (
    echo [!] Npcap not found. Downloading and installing...
    powershell -Command "Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.79.exe' -OutFile '%TEMP%\npcap_installer.exe'" 2>nul
    if exist "%TEMP%\npcap_installer.exe" (
        "%TEMP%\npcap_installer.exe" /S
        del "%TEMP%\npcap_installer.exe"
        echo [+] Npcap installed successfully.
    ) else (
        echo [!] Could not download Npcap automatically.
        echo     Please install Npcap manually from: https://npcap.com/
        echo     Then re-run this script.
        pause
        exit /b 1
    )
)

:: ── Setup Virtual Environment ─────────────────────────────────────────────────
echo.
echo [*] Setting up Python virtual environment...
if not exist ".venv" (
    %PYTHON_CMD% -m venv .venv
    echo [+] Virtual environment created.
) else (
    echo [+] Virtual environment already exists.
)

:: Activate venv
call .venv\Scripts\activate.bat
set PYTHON_CMD=.venv\Scripts\python.exe
set PIP_CMD=.venv\Scripts\pip.exe

:: ── Install Python Dependencies ───────────────────────────────────────────────
echo.
echo [*] Upgrading pip...
%PIP_CMD% install --upgrade pip -q

echo [*] Installing Python dependencies...
if exist "requirements.txt" (
    %PIP_CMD% install -r requirements.txt -q
    echo [+] All dependencies from requirements.txt installed!
) else (
    echo [!] requirements.txt not found. Installing defaults...
    %PIP_CMD% install flask scapy pyfiglet -q
    echo [+] Default dependencies installed!
)

:: ── Verify Imports ────────────────────────────────────────────────────────────
echo.
echo [*] Verifying Python imports...
%PYTHON_CMD% -c "import flask; import scapy; print('  flask OK  scapy OK')"
if %errorlevel% NEQ 0 (
    echo [ERROR] Import check failed. Please check the errors above.
    pause
    exit /b 1
)
echo [+] All imports verified!

:: ── Launch NetWatch ───────────────────────────────────────────────────────────
echo.
echo ========================================================================
echo [+] Setup complete! Launching NetWatch...
echo     Dashboard will be available at: http://127.0.0.1:5000
echo     Press Ctrl+C to stop.
echo ========================================================================
echo.

%PYTHON_CMD% netwatch.py

pause
