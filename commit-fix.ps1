Set-Location "C:\Users\PT\Desktop\HAYO\HAYO_AI_AGENT_RAILWAY"

Write-Host "[1] Removing lock files..." -ForegroundColor Yellow
Remove-Item ".git\index.lock" -Force -ErrorAction SilentlyContinue
Remove-Item ".git\HEAD.lock"  -Force -ErrorAction SilentlyContinue

Write-Host "[2] Staging files..." -ForegroundColor Yellow
git add artifacts/api-server/src/hayo/services/ai-agent.ts
git add artifacts/hayo-ai/src/pages/AIAgent.tsx
git add commit-agent-upgrades.sh
git add push-to-railway.bat
git add commit-fix.bat
git add commit-fix.ps1

Write-Host "[3] Committing..." -ForegroundColor Yellow
git -c user.email=fmf0038@gmail.com -c user.name=Ahmed commit -m "fix: spawnSync import + cleanup utility scripts"

Write-Host "[4] Pushing..." -ForegroundColor Yellow
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS! Railway deployment triggered." -ForegroundColor Green
} else {
    Write-Host "Push failed — check above." -ForegroundColor Red
}

Read-Host "Press Enter to close"
