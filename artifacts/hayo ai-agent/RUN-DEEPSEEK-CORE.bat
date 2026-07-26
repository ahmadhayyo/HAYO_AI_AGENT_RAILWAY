@echo off
chcp 65001 >nul
title DeepSeek Core v5 - Automated Pipeline
cd /d "%~dp0"
setlocal
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "PKG=%~1"
if "%PKG%"=="" set /p PKG="Target package: "
if "%PKG%"=="" ( echo [!] no package. & pause & exit /b 1 )
echo ============================================================
echo   DeepSeek Core v5 - One-Click Pipeline  ^| Target: %PKG%
echo ============================================================
echo [!] Looking for APK for static analysis...
for /f "delims=" %%i in ('dir /b *.apk 2^>nul') do set "APK=%%i"
if "%APK%"=="" (
    echo [!] No APK found in root. Running dynamic + exploit only.
    "%PY%" deepseek_pipeline.py --package %PKG% --device %HAYO_DEV% --duration 180 --aggressive
) else (
    echo [+] Found APK: %APK%
    "%PY%" deepseek_pipeline.py "%APK%" --package %PKG% --device %HAYO_DEV% --duration 180 --aggressive
)
echo.
pause
endlocal
