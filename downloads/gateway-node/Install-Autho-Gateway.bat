@echo off
setlocal enabledelayedexpansion

title Autho Gateway Installer
color 0E

echo.
echo  ========================================
echo     AUTHO GATEWAY NODE INSTALLER
echo  ========================================
echo.

:: Check for Node.js
echo [1/5] Checking for Node.js...
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  ERROR: Node.js is not installed!
    echo.
    echo  Please download and install Node.js from:
    echo  https://nodejs.org/
    echo.
    echo  After installing Node.js, run this installer again.
    echo.
    pause
    start https://nodejs.org/
    exit /b 1
)

for /f "tokens=1,2,3 delims=." %%a in ('node -v') do (
    set NODE_MAJOR=%%a
    set NODE_MAJOR=!NODE_MAJOR:v=!
)
if !NODE_MAJOR! LSS 18 (
    echo  ERROR: Node.js 18+ required. You have v!NODE_MAJOR!
    echo  Please update from https://nodejs.org/
    pause
    exit /b 1
)
echo  [OK] Node.js found

:: Create install directory
echo [2/5] Creating installation folder...
set INSTALL_DIR=%USERPROFILE%\autho-gateway-node
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo  [OK] Install folder: %INSTALL_DIR%

:: Download files
echo [3/5] Downloading gateway files...
powershell -Command "& {$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'https://autho.pinkmahi.com/downloads/gateway-node/gateway-package.js' -OutFile '%INSTALL_DIR%\gateway-package.js' -UseBasicParsing}"
if %ERRORLEVEL% NEQ 0 (
    echo  ERROR: Failed to download gateway-package.js
    pause
    exit /b 1
)
powershell -Command "& {$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'https://autho.pinkmahi.com/downloads/gateway-node/package.json' -OutFile '%INSTALL_DIR%\package.json' -UseBasicParsing}"
powershell -Command "& {$ProgressPreference='SilentlyContinue'; if (-not (Test-Path '%INSTALL_DIR%\gateway.env')) { Invoke-WebRequest -Uri 'https://autho.pinkmahi.com/downloads/gateway-node/gateway.env' -OutFile '%INSTALL_DIR%\gateway.env' -UseBasicParsing }}"
echo  [OK] Files downloaded

:: Install npm dependencies
echo [4/5] Installing dependencies (this may take a minute)...
cd /d "%INSTALL_DIR%"
call npm install --silent 2>nul
echo  [OK] Dependencies installed

:: Install cloudflared for public gateway mode
echo [5/5] Setting up public gateway support...
where cloudflared >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  Installing Cloudflare Tunnel...
    powershell -Command "& {winget install cloudflare.cloudflared --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null}" 2>nul
    if %ERRORLEVEL% EQU 0 (
        echo  [OK] Cloudflare Tunnel installed
    ) else (
        echo  [SKIP] Cloudflare Tunnel - install manually for public mode
    )
) else (
    echo  [OK] Cloudflare Tunnel already installed
)

:: Create start scripts
echo @echo off > "%INSTALL_DIR%\Start Gateway.bat"
echo cd /d "%%~dp0" >> "%INSTALL_DIR%\Start Gateway.bat"
echo node gateway-package.js >> "%INSTALL_DIR%\Start Gateway.bat"
echo pause >> "%INSTALL_DIR%\Start Gateway.bat"

echo @echo off > "%INSTALL_DIR%\Start Gateway (Public).bat"
echo cd /d "%%~dp0" >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo set GATEWAY_AUTO_PUBLIC=true >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo node gateway-package.js >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo pause >> "%INSTALL_DIR%\Start Gateway (Public).bat"

:: Create desktop shortcuts
echo Creating desktop shortcuts...
set DESKTOP=%USERPROFILE%\Desktop

powershell -Command "& {$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Autho Gateway.lnk'); $s.TargetPath = '%INSTALL_DIR%\Start Gateway.bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'Start Autho Gateway (Private Mode)'; $s.Save()}"

powershell -Command "& {$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Autho Gateway (Public).lnk'); $s.TargetPath = '%INSTALL_DIR%\Start Gateway (Public).bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'Start Autho Gateway (Public Mode)'; $s.Save()}"

echo  [OK] Desktop shortcuts created

echo.
echo  ========================================
echo     INSTALLATION COMPLETE!
echo  ========================================
echo.
echo  Two shortcuts have been added to your desktop:
echo.
echo    [Autho Gateway]          - Run locally on your PC
echo    [Autho Gateway (Public)] - Share with the world
echo.
echo  Would you like to start the gateway now?
echo.
choice /C YN /M "Start Autho Gateway"
if %ERRORLEVEL% EQU 1 (
    echo.
    echo  Starting Autho Gateway...
    start "" "%INSTALL_DIR%\Start Gateway.bat"
)

echo.
echo  Installation folder: %INSTALL_DIR%
echo  Local URL: http://localhost:3001
echo.
echo  Press any key to exit...
pause >nul
