@echo off
title HAYO Orchestrator v6
cd /d "%~dp0"
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"
if "%HAYO_DEV%"=="" set "HAYO_DEV=emulator-5554"
set "PKG=%~1"

echo HAYO Cipher-7 — Master Orchestrator v6
echo ======================================
if "%PKG%"=="" (
  echo [!] لم يتم تمرير اسم الحزمة. اختر تطبيقاً من اللوحة ثم اضغط الزر.
  "%PY%" orchestrator.py
  pause
  exit /b
)
echo   Target : %PKG%
echo   Device : %HAYO_DEV%
echo   Mode   : full-assault ^(كل الحمولات: شبكة + تشفير + firebase + billing + تخزين^)
echo.
"%PY%" orchestrator.py --full-assault %PKG% --device %HAYO_DEV% --duration 90
pause
