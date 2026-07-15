# HAYO Cipher-7 - one-click dynamic demo launcher (LDPlayer / x86_64)
# Usage:  powershell -ExecutionPolicy Bypass -File RUN-DEMO.ps1 -Package com.target.app
param(
  [Parameter(Mandatory=$true)][string]$Package,
  [int]$Duration = 120,
  [switch]$NoSpawn,
  [string]$Adb = "D:\LDPlayer\LDPlayer9\adb.exe",
  [string]$FridaServer = "$env:USERPROFILE\Downloads\frida-server-16.7.19-android-x86_64"
)
$ErrorActionPreference = "Continue"
$env:PYTHONUTF8 = "1"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
function Step($m){ Write-Host "`n[*] $m" -ForegroundColor Cyan }

if (-not (Test-Path $Adb)) { Write-Host "[!] adb not found: $Adb" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $FridaServer)) { Write-Host "[!] frida-server not found: $FridaServer" -ForegroundColor Red; exit 1 }

Step "Checking emulator connection"
$dev = (& $Adb devices | Select-String "device$")
if (-not $dev) {
  Write-Host "[!] No device ready. adb status:" -ForegroundColor Yellow
  & $Adb devices
  Write-Host "`n>> Fix: run 'adb kill-server' then 'adb start-server', wait 4s, try again." -ForegroundColor Yellow
  exit 1
}
$devId = ($dev[0] -split "\s+")[0]
Write-Host "    Device: $devId" -ForegroundColor Green

Step "Pushing and starting frida-server as root"
& $Adb -s $devId push $FridaServer /data/local/tmp/frida-server | Out-Null
& $Adb -s $devId shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
& $Adb -s $devId shell "su -c 'pkill -f frida-server 2>/dev/null; true'"
Start-Process -FilePath $Adb -ArgumentList "-s",$devId,"shell","su -c '/data/local/tmp/frida-server &'" -WindowStyle Hidden
Start-Sleep -Seconds 2
$fs = & $Adb -s $devId shell "ps -A 2>/dev/null | grep frida-server"
if ($fs) { Write-Host "    frida-server running [OK]" -ForegroundColor Green }
else { Write-Host "    [!] frida-server not confirmed - continuing anyway." -ForegroundColor Yellow }

Step "Checking target app is installed: $Package"
$inst = & $Adb -s $devId shell "pm list packages $Package"
if (-not $inst) { Write-Host "    [!] App not installed on the emulator. Install it first." -ForegroundColor Red; exit 1 }
Write-Host "    Installed [OK]" -ForegroundColor Green

Step "Launching live dynamic demo (frida)"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$demoArgs = @("-3.12","-u","$here\demo.py","--package",$Package,"--device",$devId,"--duration","$Duration")
if (-not $NoSpawn) { $demoArgs += "--spawn" }
& py @demoArgs
