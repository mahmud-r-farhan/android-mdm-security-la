@echo off
REM ============================================================================
REM Android Enterprise Security Lab - One-Click Windows Launcher
REM File: scripts/setup.bat
REM Description: Double-click entry point for non-technical users. Runs the
REM              PowerShell setup with a permissive execution policy, then
REM              offers to launch the MDM inspector immediately.
REM License: Apache License 2.0
REM ============================================================================

setlocal
title Android Enterprise Security Lab - Setup
cd /d "%~dp0.."

echo ====================================================================
echo    Android Enterprise Security Lab - One-Click Setup
echo ====================================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
set "SETUP_RC=%ERRORLEVEL%"

if %SETUP_RC% neq 0 (
    echo.
    echo [!] Setup finished with warnings ^(exit code %SETUP_RC%^).
)

echo.
set /p RUN_INSPECTOR="Launch the MDM inspector now? (y/N): "
if /i "%RUN_INSPECTOR%"=="y" (
    where python >nul 2>nul
    if %ERRORLEVEL%==0 (
        python core\mdm_inspector.py
    ) else (
        echo [X] Python was not found on PATH. Install Python 3.9+ and retry.
    )
)

echo.
pause
endlocal
