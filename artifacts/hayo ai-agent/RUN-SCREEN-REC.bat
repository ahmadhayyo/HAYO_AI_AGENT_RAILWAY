@echo off
title HAYO Screen Recorder
cd /d "%~dp0"

REM ============================================================
REM  HAYO Cipher-7 — SCREEN RECORDER
REM  Linked to Emulator: emulator-5554
REM ============================================================

if not defined HAYO_DEV set "HAYO_DEV=emulator-5554"
set "DEV=%HAYO_DEV%"
set "PY=C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"

set /p DUR="Duration (seconds, default 60): "
if "%DUR%"=="" set DUR=60

"%PY%" screen_recorder.py --duration %DUR% --device %DEV%
pause
