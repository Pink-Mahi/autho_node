# Autho Operator Node - PowerShell Installer
# Usage: irm https://autho.pinkmahi.com/downloads/operator-node/quick-install.ps1 | iex

Write-Host "⚡ Autho Operator Node - Quick Installer" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
try {
    $nodeVersion = node --version
    $majorVersion = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')

    if ($majorVersion -lt 18) {
        Write-Host "❌ Node.js 18+ required. Current: $nodeVersion" -ForegroundColor Red
        Write-Host "   Download from: https://nodejs.org/" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "✅ Node.js $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js is not installed" -ForegroundColor Red
    Write-Host "   Please install Node.js 18+ from: https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

# Check Git
try {
    $gitVersion = git --version
    Write-Host "✅ $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Git is not installed" -ForegroundColor Red
    Write-Host "   Please install Git from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

$installDir = "$env:USERPROFILE\autho-operator-node"
$repoUrl = "https://github.com/Pink-Mahi/autho.git"

Write-Host "📁 Installing to: $installDir" -ForegroundColor Cyan

if (Test-Path "$installDir\.git") {
    Write-Host "🔄 Existing install found, pulling latest..." -ForegroundColor Cyan
    Push-Location $installDir
    git pull --ff-only
    Pop-Location
} else {
    if (Test-Path $installDir) {
        Remove-Item -Recurse -Force $installDir
    }
    git clone $repoUrl $installDir
}

Push-Location $installDir

Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
npm install --silent | Out-Null

Write-Host "🏗️  Building..." -ForegroundColor Cyan
npm run build --silent | Out-Null

# Create start scripts
$startBat = @"
@echo off
cd /d "%~dp0"
npm run operator
pause
"@
Set-Content -Path "$installDir\start.bat" -Value $startBat

$startPs1 = @"
Set-Location `$PSScriptRoot
npm run operator
"@
Set-Content -Path "$installDir\start.ps1" -Value $startPs1

Pop-Location

Write-Host "✅ Installed." -ForegroundColor Green
Write-Host "   Start with: $installDir\start.bat" -ForegroundColor Yellow
