@echo off
REM Autho Gateway Node - One-Line Installer for Windows
REM Usage: powershell -c "irm https://autho.pinkmahi.com/downloads/gateway-node/quick-install.bat | iex"

echo 🌐 Autho Gateway Node - Quick Installer
echo ========================================

REM Check Node.js
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Node.js is not installed
    echo    Please install Node.js 18+ from: https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js found
node --version

REM Create installation directory
set INSTALL_DIR=%USERPROFILE%\autho-gateway-node
echo 📁 Installing to: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download files
echo 📥 Downloading gateway node...
cd /d "%INSTALL_DIR%"
for /f %%i in ('powershell -NoProfile -Command "[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()"') do set CACHE_BUST=%%i

powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri 'https://autho.pinkmahi.com/downloads/gateway-node/gateway-package.js?v=%CACHE_BUST%' -OutFile 'gateway-package.js' | Out-Null"
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to download gateway-package.js
    pause
    exit /b 1
)

powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri 'https://autho.pinkmahi.com/downloads/gateway-node/package.json?v=%CACHE_BUST%' -OutFile 'package.json' | Out-Null"
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to download package.json
    pause
    exit /b 1
)

REM Install dependencies
echo 📦 Installing dependencies...
call npm install --silent

REM Create start script
echo @echo off > start.bat
echo cd /d "%%~dp0" >> start.bat
echo set AUTHO_OPERATOR_URLS=http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com >> start.bat
echo node gateway-package.js >> start.bat

echo.
echo ✅ Installation complete!
echo.
echo 🚀 Start the gateway node:
echo    cd %INSTALL_DIR%
echo    start.bat
echo.
echo 🌐 Gateway will run on: http://localhost:3001
echo 📊 Health check: http://localhost:3001/health
echo.
echo 🎉 Welcome to the Autho network!
echo.
pause
