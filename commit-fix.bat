@echo off
cd /d "C:\Users\PT\Desktop\HAYO\HAYO_AI_AGENT_RAILWAY"

echo [1] Killing any stale git processes...
taskkill /f /im git.exe 2>nul

echo [2] Removing lock files...
del /f ".git\index.lock" 2>nul
del /f ".git\HEAD.lock" 2>nul

echo [3] Staging files...
git add artifacts/api-server/src/hayo/services/ai-agent.ts
git add artifacts/hayo-ai/src/pages/AIAgent.tsx
git add commit-agent-upgrades.sh
git add push-to-railway.bat

echo [4] Committing...
git -c user.email=fmf0038@gmail.com -c user.name=Ahmed commit -m "fix: spawnSync import + streaming agent upgrades cleanup"

echo [5] Pushing to Railway...
git push origin main

echo.
echo ====================================================
if %ERRORLEVEL%==0 (
    echo  SUCCESS! Railway deployment triggered.
) else (
    echo  Check errors above.
)
echo ====================================================
pause
