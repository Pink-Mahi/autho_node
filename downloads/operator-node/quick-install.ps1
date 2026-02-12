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

# --- Auto-setup TURN (coturn) + secret ---
$turnDir = Join-Path $installDir "operator-data"
New-Item -ItemType Directory -Force -Path $turnDir | Out-Null

$secretBytes = New-Object byte[] 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($secretBytes)
$turnSecret = ($secretBytes | ForEach-Object { $_.ToString('x2') }) -join ''

$turnJson = @{
    username   = "autho"
    credential = $turnSecret
} | ConvertTo-Json

Set-Content -Path (Join-Path $turnDir "turn.json") -Value $turnJson -Encoding UTF8
Write-Host "🔐 TURN secret generated" -ForegroundColor Green

$dockerAvailable = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerAvailable) {
    Write-Host "🧩 Starting coturn via Docker..." -ForegroundColor Cyan
    try {
        docker rm -f autho-turn 2>$null | Out-Null
        docker run -d --name autho-turn --restart unless-stopped `
          -p 3478:3478/tcp -p 3478:3478/udp `
          -p 49152-49200:49152-49200/udp `
          instrumentisto/coturn `
          -n --log-file=stdout --use-auth-secret --static-auth-secret=$turnSecret `
          --realm=autho --min-port=49152 --max-port=49200 | Out-Null
        Write-Host "✅ coturn running (Docker)" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Could not start coturn via Docker" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  Docker not found. To enable TURN on Windows, install Docker Desktop or use WSL." -ForegroundColor Yellow
}

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
