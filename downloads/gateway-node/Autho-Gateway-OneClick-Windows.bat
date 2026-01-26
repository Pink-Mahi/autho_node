@echo off
setlocal enabledelayedexpansion

echo ==============================================
echo  Autho Gateway Node - One-Click Windows Setup
echo ==============================================

REM Install directory
set "INSTALL_DIR=%USERPROFILE%\autho-gateway-node"

REM Check Node.js
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo ERROR: Node.js is not installed.
  echo Please install Node.js 18+ from https://nodejs.org/
  echo.
  start "" "https://nodejs.org/"
  pause
  exit /b 1
)

REM Check npm
where npm >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo ERROR: npm was not found.
  echo Reinstall Node.js (it includes npm): https://nodejs.org/
  echo.
  start "" "https://nodejs.org/"
  pause
  exit /b 1
)

echo ✅ Node: 
node --version

if not exist "%INSTALL_DIR%" (
  echo 📁 Creating: %INSTALL_DIR%
  mkdir "%INSTALL_DIR%" >nul 2>nul
)

cd /d "%INSTALL_DIR%"

echo 📥 Downloading gateway files...
set "BASE_URL=https://autho.pinkmahi.com/downloads/gateway-node"

for /f %%i in ('powershell -NoProfile -Command "[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()"') do set CACHE_BUST=%%i

powershell -NoProfile -Command "$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%BASE_URL%/gateway-package.js?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'gateway-package.js' -UseBasicParsing | Out-Null; exit 0 } catch { Write-Host $_; exit 1 }" 
if %ERRORLEVEL% NEQ 0 (
  echo ERROR: Failed to download gateway-package.js
  pause
  exit /b 1
)

powershell -NoProfile -Command "$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%BASE_URL%/package.json?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'package.json' -UseBasicParsing | Out-Null; exit 0 } catch { Write-Host $_; exit 1 }" 
if %ERRORLEVEL% NEQ 0 (
  echo ERROR: Failed to download package.json
  pause
  exit /b 1
)

powershell -NoProfile -Command "Invoke-WebRequest -Uri '%BASE_URL%/Start-Autho-Gateway-Node.bat?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'Start-Autho-Gateway-Node.bat' -UseBasicParsing" >nul 2>nul
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%BASE_URL%/Start-Autho-Gateway-Node-Background.bat?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'Start-Autho-Gateway-Node-Background.bat' -UseBasicParsing" >nul 2>nul

if not exist "node_modules" (
  echo 📦 Installing dependencies (first run)...
  call npm install
  if %ERRORLEVEL% NEQ 0 (
    echo ERROR: npm install failed.
    pause
    exit /b 1
  )
) else (
  echo ✅ Dependencies already installed.
)

echo.
echo 🚀 Starting gateway node...
echo    Logs: %INSTALL_DIR%\gateway-node.log
echo.

REM Start in a visible window so failures don't disappear instantly
start "Autho Gateway Node" cmd /k "cd /d \"%INSTALL_DIR%\" ^&^& set GATEWAY_PORT=3001 ^&^& set AUTHO_OPERATOR_URLS=http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com ^&^& node gateway-package.js 1^> gateway-node.log 2^>^&1"

REM Give it a moment then open the UI
timeout /t 4 /nobreak >nul

REM Verify it actually started
powershell -NoProfile -Command "$u='http://localhost:3001/health'; try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri $u; if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) { exit 0 } else { exit 1 } } catch { exit 1 }"
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo ERROR: Gateway did not start successfully on http://localhost:3001
  echo.
  echo --- Last log lines (%INSTALL_DIR%\gateway-node.log) ---
  powershell -NoProfile -Command "$p = Join-Path $env:USERPROFILE 'autho-gateway-node\\gateway-node.log'; if (Test-Path $p) { Get-Content $p -Tail 120 } else { Write-Host 'No log found at' $p }"
  echo.
  echo Common causes:
  echo   - Port 3001 already in use (EADDRINUSE)
  echo   - Node dependencies failed to install
  echo   - Antivirus/Defender blocked node from listening
  echo.
  pause
  exit /b 1
)

start "" "http://localhost:3001/m"

echo ✅ Opened: http://localhost:3001/m
echo.
echo Tip: Next time you can just double-click:
echo   %INSTALL_DIR%\Start-Autho-Gateway-Node.bat
echo.
pause
exit /b 0
