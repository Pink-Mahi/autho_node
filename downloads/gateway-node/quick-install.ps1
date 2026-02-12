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

    if (-not (Test-Path "$installDir\gateway.env")) {
        Invoke-WebRequest -Uri "$baseUrl/gateway.env?v=$cacheBust" -Headers $headers -OutFile "$installDir\gateway.env" -UseBasicParsing
    }
    
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

# --- Auto-setup TURN (coturn) + secret ---
$turnDir = Join-Path $installDir "gateway-data"
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

# Install cloudflared for public access (optional but recommended)
Write-Host "🌐 Checking for Cloudflare Tunnel (cloudflared)..." -ForegroundColor Cyan

$cloudflaredInstalled = $false
$cloudflaredPaths = @(
    "cloudflared",
    "C:\Program Files (x86)\cloudflared\cloudflared.exe",
    "C:\Program Files\cloudflared\cloudflared.exe"
)

foreach ($cfPath in $cloudflaredPaths) {
    try {
        & $cfPath --version 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $cloudflaredInstalled = $true
            Write-Host "✅ cloudflared already installed" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $cloudflaredInstalled) {
    Write-Host "📥 Installing cloudflared for public gateway access..." -ForegroundColor Cyan
    try {
        # Try winget first
        $wingetAvailable = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetAvailable) {
            winget install cloudflare.cloudflared --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
            Write-Host "✅ cloudflared installed via winget" -ForegroundColor Green
        } else {
            # Download directly
            $cfUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.msi"
            $cfMsi = "$env:TEMP\cloudflared.msi"
            Invoke-WebRequest -Uri $cfUrl -OutFile $cfMsi -UseBasicParsing
            Start-Process msiexec.exe -ArgumentList "/i `"$cfMsi`" /quiet /norestart" -Wait
            Remove-Item $cfMsi -Force -ErrorAction SilentlyContinue
            Write-Host "✅ cloudflared installed" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️  Could not install cloudflared automatically" -ForegroundColor Yellow
        Write-Host "   For public gateway access, install manually:" -ForegroundColor Yellow
        Write-Host "   winget install cloudflare.cloudflared" -ForegroundColor White
    }
}

# Create start script (private mode - local only)
$startScript = @"
@echo off
cd /d "%~dp0"
set AUTHO_OPERATOR_URLS=http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com
node gateway-package.js
pause
"@

Set-Content -Path "$installDir\start.bat" -Value $startScript
Write-Host "✅ Created start script (private mode)" -ForegroundColor Green

# Create PowerShell start script (private mode)
$psStartScript = @"
Set-Location `$PSScriptRoot
`$env:AUTHO_OPERATOR_URLS = 'http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com'
node gateway-package.js
"@

Set-Content -Path "$installDir\start.ps1" -Value $psStartScript

# Create PUBLIC start script (with Cloudflare Tunnel)
$publicStartScript = @"
@echo off
cd /d "%~dp0"
set AUTHO_OPERATOR_URLS=http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com
set GATEWAY_AUTO_PUBLIC=true
node gateway-package.js
pause
"@

Set-Content -Path "$installDir\start-public.bat" -Value $publicStartScript
Write-Host "✅ Created public start script" -ForegroundColor Green

# Create PowerShell PUBLIC start script
$psPublicStartScript = @"
Set-Location `$PSScriptRoot
`$env:AUTHO_OPERATOR_URLS = 'http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com'
`$env:GATEWAY_AUTO_PUBLIC = 'true'
node gateway-package.js
"@

Set-Content -Path "$installDir\start-public.ps1" -Value $psPublicStartScript

# Create Desktop Shortcuts
Write-Host "🖥️  Creating desktop shortcuts..." -ForegroundColor Cyan

$desktopPath = [Environment]::GetFolderPath('Desktop')
$WshShell = New-Object -ComObject WScript.Shell

# Private Gateway shortcut
$privateShortcut = $WshShell.CreateShortcut("$desktopPath\Autho Gateway.lnk")
$privateShortcut.TargetPath = "powershell.exe"
$privateShortcut.Arguments = "-ExecutionPolicy Bypass -File `"$installDir\start.ps1`""
$privateShortcut.WorkingDirectory = $installDir
$privateShortcut.Description = "Start Autho Gateway (Private Mode)"
$privateShortcut.Save()

# Public Gateway shortcut
$publicShortcut = $WshShell.CreateShortcut("$desktopPath\Autho Gateway (Public).lnk")
$publicShortcut.TargetPath = "powershell.exe"
$publicShortcut.Arguments = "-ExecutionPolicy Bypass -File `"$installDir\start-public.ps1`""
$publicShortcut.WorkingDirectory = $installDir
$publicShortcut.Description = "Start Autho Gateway (Public Mode with Cloudflare Tunnel)"
$publicShortcut.Save()

Write-Host "✅ Desktop shortcuts created" -ForegroundColor Green

Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "�️  Desktop shortcuts created:" -ForegroundColor Cyan
Write-Host "   • Autho Gateway - Private mode (local only)" -ForegroundColor White
Write-Host "   • Autho Gateway (Public) - Public mode with Cloudflare Tunnel" -ForegroundColor White
Write-Host ""
Write-Host "🚀 Or run from command line:" -ForegroundColor Cyan
Write-Host "   cd $installDir" -ForegroundColor White
Write-Host "   .\start.ps1          (private)" -ForegroundColor White
Write-Host "   .\start-public.ps1   (public)" -ForegroundColor White
Write-Host ""
Write-Host "🌐 Local Gateway: http://localhost:3001" -ForegroundColor Cyan
Write-Host "📊 Health check: http://localhost:3001/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎉 Welcome to the Autho network!" -ForegroundColor Green
Write-Host ""
