# Autho Gateway - One-Line Installer for Windows
# Usage: irm https://autho.pinkmahi.com/install-gateway.ps1 | iex
#
# This script downloads and runs an Autho Gateway node.

$ErrorActionPreference = "Stop"

Write-Host "🌐 Autho Gateway Node - Windows Installer" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Node.js
try {
    $nodeVersion = node -v
    $majorVersion = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
    if ($majorVersion -lt 18) {
        Write-Host "❌ Node.js 18+ required. You have: $nodeVersion" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Node.js $nodeVersion detected" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js is required but not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install Node.js from: https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

# Create directory
$InstallDir = if ($env:AUTHO_INSTALL_DIR) { $env:AUTHO_INSTALL_DIR } else { "$env:USERPROFILE\autho-gateway" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Set-Location $InstallDir

Write-Host "📁 Installing to: $InstallDir" -ForegroundColor Cyan

# Download gateway package
Write-Host "⬇️  Downloading gateway package..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://autho.pinkmahi.com/api/gateway/download/gateway-package.js" -OutFile "gateway-package.js"
Invoke-WebRequest -Uri "https://autho.pinkmahi.com/api/gateway/download/package.json" -OutFile "package.json"

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
npm install --production --silent

# Create start script
@"
@echo off
cd /d "%~dp0"
node gateway-package.js
pause
"@ | Out-File -FilePath "start.bat" -Encoding ASCII

Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 To start the gateway:" -ForegroundColor Cyan
Write-Host "   cd $InstallDir" -ForegroundColor White
Write-Host "   .\start.bat" -ForegroundColor White
Write-Host ""
Write-Host "📊 Once running, check health at:" -ForegroundColor Cyan
Write-Host "   http://localhost:3001/health" -ForegroundColor White
Write-Host ""
Write-Host "🌍 To run as a PUBLIC gateway:" -ForegroundColor Cyan
Write-Host '   $env:GATEWAY_PUBLIC="true"' -ForegroundColor White
Write-Host '   $env:GATEWAY_PUBLIC_URL="https://your-domain.com"' -ForegroundColor White
Write-Host "   node gateway-package.js" -ForegroundColor White
Write-Host ""
