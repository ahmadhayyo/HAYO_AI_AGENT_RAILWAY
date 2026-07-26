@echo off
REM ============================================================
REM  HAYO Cipher-7 — Cloud interception launcher (waf+cloud breaker)
REM  Usage:  RUN-HIJACK-CLOUD.bat  com.package.name
REM ============================================================
setlocal
set "ADB=C:\Users\PT\Downloads\platform-tools\adb.exe"
set "PY312=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "DEV=%HAYO_DEV%"

if "%~1"=="" (
  echo [!] Usage: RUN-HIJACK-CLOUD.bat ^<package.name^>
  exit /b 1
)

echo [*] Starting frida-server ...
start "HAYO frida-server" /min "%ADB%" -s %DEV% shell "su -c '/data/local/tmp/frida-server'"
ping -n 4 127.0.0.1 >nul

echo [*] Launching HAYO Cloud interception on %~1 (WAF bypass + cloud breaker) ...
"%PY312%" "%~dp0frida_hijack.py" -D %DEV% -m cloud %~1
endlocal
