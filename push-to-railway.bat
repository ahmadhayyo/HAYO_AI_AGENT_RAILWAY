@echo off
cd /d "%~dp0"
echo ====================================================
echo  HAYO AI Agent - Pushing to Railway
echo ====================================================
echo.

echo [1] Removing stale git lock (if any)...
if exist ".git\index.lock" del /f ".git\index.lock"

echo [2] Git status...
git status

echo.
echo [3] Pushing commit to origin/main...
git push origin main

echo.
if %ERRORLEVEL%==0 (
    echo ====================================================
    echo  SUCCESS! Railway will start rebuilding now.
    echo  Check: https://railway.app/dashboard
    echo ====================================================
) else (
    echo ====================================================
    echo  PUSH FAILED. Check git credentials above.
    echo ====================================================
)

pause
