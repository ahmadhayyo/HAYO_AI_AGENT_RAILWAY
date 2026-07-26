@echo off
REM  HAYO Cipher-7 — verify + auto-repair the environment before the exam.
set "PY312=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
"%PY312%" "%~dp0setup_check.py"
echo.
pause
