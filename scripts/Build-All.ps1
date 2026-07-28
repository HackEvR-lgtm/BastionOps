#Requires -RunAsAdministrator
param([switch]$BuildDriver)

$SCRIPT_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent $SCRIPT_ROOT

Write-Host "[*] Building CDS v2.0 User-Mode Daemon..." -ForegroundColor Cyan
Push-Location (Join-Path $PROJECT_ROOT "src\usermode")
dotnet build -c Release
Pop-Location

if ($BuildDriver) {
    Write-Host "[*] Building CDS v2.0 Kernel-Mode Driver (Requires WDK)..." -ForegroundColor Cyan
    # Stub for WDK build. Actual compilation requires msbuild with WDK targets.
    # msbuild (Join-Path $PROJECT_ROOT "src\kernelmode\CdsProtectDriver.vcxproj") /p:Configuration=Release /p:Platform=x64
    Write-Host "[!] Kernel driver build stub executed. Manual WDK build required for production signing." -ForegroundColor Yellow
}

Write-Host "[+] Build process completed." -ForegroundColor Green
