@echo off
title HAYO Cipher-7 GUI
cd /d "%~dp0"

REM ============================================================
REM  HAYO Cipher-7 — UNIFIED GRAPHICAL INTERFACE
REM  Linked to Emulator: emulator-5554
REM ============================================================

set "PYW=C:\Users\PT\AppData\Local\Programs\Python\Python312\pythonw.exe"

echo [*] Launching HAYO Cipher-7 Unified Control Panel...
start "" "%PYW%" "%~dp0HAYO-GUI.pyw"
exit
