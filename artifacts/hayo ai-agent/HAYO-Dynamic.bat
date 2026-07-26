@echo off
chcp 65001 >nul
title HAYO Cipher-7 - Dynamic Analysis (One Click)
cd /d "%~dp0"

echo ============================================================
echo   HAYO Cipher-7 - التحليل الديناميكي (نقرة واحدة)
echo ============================================================
echo.

REM 1) Locate Python 3.12 (its Frida 16.x matches frida-server; the default
REM    python is 3.14 with Frida 17 which CANNOT talk to a 16.x server).
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%PY%" (
  py -3.12 -c "import sys" >nul 2>nul
  if errorlevel 1 (
    echo [!] Python 3.12 غير موجود. ثبّته من python.org ^(الإصدار 3.12^) ثم أعد المحاولة.
    pause
    exit /b 1
  )
  set "PY=py -3.12"
)

REM 2) Install dependencies (quiet; first run only, then cached)
echo [*] التحقق من المكتبات...
%PY% -m pip install -q -r requirements.txt

REM 3) Token: use saved token.txt if present, else ask once
set "TOKEN="
if exist "token.txt" set /p TOKEN=<token.txt
if not defined TOKEN (
  echo.
  echo الصق الرمز من التقرير ^(يبدأ بـ dyn_^) ثم اضغط Enter:
  set /p TOKEN=Token:
)
if not defined TOKEN (
  echo [!] لم تُدخل رمزاً. أعد التشغيل والصق الرمز من التقرير.
  pause
  exit /b 1
)

echo.
echo [*] كل شيء تلقائي من الآن: المحاكي + frida-server + اسم التطبيق.
echo.

REM 4) Run the auto-runner (auto device / frida / package detection)
%PY% auto.py --token %TOKEN%

echo.
echo تم. حدّث التقرير في المنصة لرؤية النتائج الديناميكية.
pause
