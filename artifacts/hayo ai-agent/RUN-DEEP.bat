@echo off
chcp 65001 >nul
title HAYO Cipher-7 — Deep AI Engine
cd /d "%~dp0"
setlocal
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"

set "PKG=%~1"
if "%PKG%"=="" set /p PKG="Target package: "
if "%PKG%"=="" ( echo [!] no package. & pause & exit /b 1 )

set "DUR=%~2"
if "%DUR%"=="" set "DUR=180"

echo ============================================================
echo   HAYO Cipher-7 — المحرك الديناميكي الموحّد (عقل DeepSeek)
echo   Target: %PKG%   Device: %HAYO_DEV%   Window: %DUR%s
echo ============================================================
echo   العقل يقود التطبيق تلقائياً نحو تسجيل الدخول/المزايا المدفوعة/السحابة.
echo   النتائج تُفرز وتُحفظ في loot\deep_*.md  و  loot\deep_*.json
echo ============================================================
echo.
"%PY%" dynamic_engine.py --package %PKG% --device %HAYO_DEV% --duration %DUR%
echo.
echo تم. افتح تقرير loot\deep_*.md لرؤية النتائج المفرزة.
pause
endlocal
