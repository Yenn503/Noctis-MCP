@echo off
REM Noctis-MCP Setup Launcher (Windows)
REM ====================================
REM Simple batch file to launch PowerShell setup script

REM Get the directory of this script and change to repo root
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%..\..\"

echo.
echo ================================================
echo   Noctis-MCP Windows Setup
echo ================================================
echo.
echo Repository: %CD%
echo.

REM Check if PowerShell is available
where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: PowerShell not found!
    echo PowerShell is required for setup.
    pause
    exit /b 1
)

REM Run PowerShell setup script
echo Starting PowerShell setup script...
echo.
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%setup.ps1"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================
    echo   Setup completed successfully!
    echo ================================================
) else (
    echo.
    echo ================================================
    echo   Setup encountered errors
    echo ================================================
)

echo.
pause

