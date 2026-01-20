# Autho Gateway Node - PowerShell Installer
# Usage: irm https://autho.pinkmahi.com/downloads/gateway-node/quick-install.ps1 | iex

Write-Host "🌐 Autho Gateway Node - Quick Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
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

# Create installation directory
$installDir = "$env:USERPROFILE\autho-gateway-node"
Write-Host "📁 Installing to: $installDir" -ForegroundColor Cyan

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Write-Host "✅ Created installation directory" -ForegroundColor Green
}

# Download files
Write-Host "📥 Downloading gateway node..." -ForegroundColor Cyan

try {
    $baseUrl = "https://autho.pinkmahi.com/downloads/gateway-node"
    $cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $headers = @{ 'Cache-Control' = 'no-cache'; 'Pragma' = 'no-cache' }
    
    Invoke-WebRequest -Uri "$baseUrl/gateway-package.js?v=$cacheBust" -Headers $headers -OutFile "$installDir\gateway-package.js" -UseBasicParsing
    Invoke-WebRequest -Uri "$baseUrl/package.json?v=$cacheBust" -Headers $headers -OutFile "$installDir\package.json" -UseBasicParsing
    
    Write-Host "✅ Files downloaded" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to download files: $_" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
Push-Location $installDir

try {
    npm install --silent 2>&1 | Out-Null
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Warning: npm install had issues, but continuing..." -ForegroundColor Yellow
}

Pop-Location

# Create start script
$startScript = @"
@echo off
cd /d "%~dp0"
set AUTHO_OPERATOR_URLS=http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com
node gateway-package.js
pause
"@

Set-Content -Path "$installDir\start.bat" -Value $startScript
Write-Host "✅ Created start script" -ForegroundColor Green

# Create PowerShell start script
$psStartScript = @"
Set-Location `$PSScriptRoot
`$env:AUTHO_OPERATOR_URLS = 'http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com'
node gateway-package.js
"@

Set-Content -Path "$installDir\start.ps1" -Value $psStartScript
Write-Host "✅ Created PowerShell start script" -ForegroundColor Green

Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 To start the gateway node:" -ForegroundColor Cyan
Write-Host "   cd $installDir" -ForegroundColor White
Write-Host "   .\start.ps1" -ForegroundColor White
Write-Host ""
Write-Host "   Or double-click: start.bat" -ForegroundColor White
Write-Host ""
Write-Host "🌐 Gateway will run on: http://localhost:3001" -ForegroundColor Cyan
Write-Host "📊 Health check: http://localhost:3001/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎉 Welcome to the Autho network!" -ForegroundColor Green
Write-Host ""
