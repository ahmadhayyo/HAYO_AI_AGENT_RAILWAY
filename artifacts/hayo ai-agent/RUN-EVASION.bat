@echo off
REM ============================================================
REM  HAYO Cipher-7 — Anti-detection / Evasion launcher
REM  Usage:  RUN-EVASION.bat  com.target.package   (or run and type it)
REM  Targets the EMULATOR only (safe while a real phone is attached).
REM ============================================================
title HAYO Evasion
cd /d "%~dp0"
set "ADB=C:\Users\PT\Downloads\platform-tools\adb.exe"
if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "DEV=%HAYO_DEV%"

set "PKG=%~1"
if "%PKG%"=="" set /p PKG="Target package: "
if "%PKG%"=="" (echo [!] No package given & pause & exit /b 1)

echo [*] Starting frida-server on %DEV% (leave this window open) ...
start "HAYO frida-server" /min "%ADB%" -s %DEV% shell "su -c '/data/local/tmp/frida-server'"
ping -n 4 127.0.0.1 >nul

echo [*] Injecting evasion payload into %PKG% on %DEV% ...
frida -D %DEV% -f %PKG% -l payload_evasion.js
pause
