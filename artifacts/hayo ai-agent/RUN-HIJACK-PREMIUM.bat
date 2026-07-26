@echo off
REM ============================================================
REM  HAYO Cipher-7 — Premium unlock + token injection launcher
REM  Usage:  RUN-HIJACK-PREMIUM.bat  com.package.name
REM ============================================================
setlocal
set "ADB=C:\Users\PT\Downloads\platform-tools\adb.exe"
set "PY312=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "DEV=%HAYO_DEV%"

if "%~1"=="" (
  echo [!] Usage: RUN-HIJACK-PREMIUM.bat ^<package.name^>
  exit /b 1
)

echo [*] Starting frida-server ...
start "HAYO frida-server" /min "%ADB%" -s %DEV% shell "su -c '/data/local/tmp/frida-server'"
ping -n 4 127.0.0.1 >nul

echo [*] Launching HAYO Premium Unlock + Token Injection on %~1 ...
"%PY312%" "%~dp0frida_hijack.py" -D %DEV% -m premium %~1
echo.
echo Also running token forger for offline token generation...
"%PY312%" "%~dp0token_forger.py" --premium-jwt --receipt --package %~1 --output loot/token_forge
endlocal
