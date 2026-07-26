@echo off
REM ============================================================
REM  HAYO Cipher-7 — Local APK Modify + Rebuild + Sign (no Railway needed)
REM  Usage:  RUN-MODIFY-APK.bat  committee.apk  [--root]
REM  (or just drag the APK file onto this .bat)
REM  Output: <name>_modified.apk  — signed, aligned, ready to adb install.
REM ============================================================
setlocal
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"

if "%~1"=="" (
  echo [!] Usage: RUN-MODIFY-APK.bat ^<committee.apk^> [--root]
  echo     Tip: you can also drag the APK file onto this .bat
  pause
  exit /b 1
)

"%PY%" "%~dp0modify_apk.py" %*
echo.
pause
endlocal
