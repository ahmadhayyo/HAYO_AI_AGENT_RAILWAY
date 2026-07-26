@echo off
title HAYO Data Cloner
cd /d "%~dp0"
if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "DEV=%HAYO_DEV%"
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"

set "PKG=%~1"
if "%PKG%"=="" set /p PKG="Target package: "
if "%PKG%"=="" (echo [!] No package given & pause & exit /b 1)

"%PY%" data_cloner.py --package %PKG% --device %DEV%
pause
