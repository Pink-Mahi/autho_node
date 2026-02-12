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
echo [1/6] Checking for Node.js...
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
echo [2/6] Creating installation folder...
set INSTALL_DIR=%USERPROFILE%\autho-gateway-node
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo  [OK] Install folder: %INSTALL_DIR%

:: Download files
echo [3/6] Downloading gateway files...
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
echo [4/6] Installing dependencies (this may take a minute)...
cd /d "%INSTALL_DIR%"
call npm install --silent 2>nul
echo  [OK] Dependencies installed

:: Auto-setup TURN (coturn) + secret
if not exist "%INSTALL_DIR%\gateway-data" mkdir "%INSTALL_DIR%\gateway-data"
for /f "delims=" %%s in ('powershell -NoProfile -Command "[Guid]::NewGuid().ToString('N')"') do set TURN_SECRET=%%s
(
echo {"username":"autho","credential":"%TURN_SECRET%"}
) > "%INSTALL_DIR%\gateway-data\turn.json"

where docker >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  Starting coturn via Docker...
    docker rm -f autho-turn >nul 2>&1
    docker run -d --name autho-turn --restart unless-stopped -p 3478:3478/tcp -p 3478:3478/udp -p 49152-49200:49152-49200/udp instrumentisto/coturn -n --log-file=stdout --use-auth-secret --static-auth-secret=%TURN_SECRET% --realm=autho --min-port=49152 --max-port=49200 >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo  [OK] coturn running (Docker)
    ) else (
        echo  [WARN] Could not start coturn via Docker
    )
) else (
    echo  [WARN] Docker not found. Install Docker Desktop or use WSL for TURN.
)

:: Install cloudflared for public gateway mode
echo [5/6] Setting up public gateway support...
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

:: Create Autho icon (Black background, Gold "A")
echo [6/6] Creating shortcuts with Autho branding...
powershell -ExecutionPolicy Bypass -Command ^
"Add-Type -AssemblyName System.Drawing; ^
$ico = '%INSTALL_DIR%\autho.ico'; ^
$bmp = New-Object System.Drawing.Bitmap(256,256); ^
$g = [System.Drawing.Graphics]::FromImage($bmp); ^
$g.SmoothingMode = 'AntiAlias'; ^
$g.Clear([System.Drawing.Color]::FromArgb(20,20,20)); ^
$gold = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255,215,0)); ^
$font = New-Object System.Drawing.Font('Arial',180,[System.Drawing.FontStyle]::Bold); ^
$sf = New-Object System.Drawing.StringFormat; ^
$sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'; ^
$g.DrawString('A',$font,$gold,[System.Drawing.RectangleF]::new(0,0,256,256),$sf); ^
$g.Dispose(); ^
$bmp.Save($ico,[System.Drawing.Imaging.ImageFormat]::Icon); ^
$bmp.Dispose()"

:: Create start scripts
echo @echo off > "%INSTALL_DIR%\Start Gateway.bat"
echo title Autho Gateway Node >> "%INSTALL_DIR%\Start Gateway.bat"
echo cd /d "%%~dp0" >> "%INSTALL_DIR%\Start Gateway.bat"
echo echo Starting Autho Gateway... >> "%INSTALL_DIR%\Start Gateway.bat"
echo echo. >> "%INSTALL_DIR%\Start Gateway.bat"
echo echo Once started, open: http://localhost:3001 >> "%INSTALL_DIR%\Start Gateway.bat"
echo echo. >> "%INSTALL_DIR%\Start Gateway.bat"
echo node gateway-package.js >> "%INSTALL_DIR%\Start Gateway.bat"
echo pause >> "%INSTALL_DIR%\Start Gateway.bat"

echo @echo off > "%INSTALL_DIR%\Start Gateway (Public).bat"
echo title Autho Gateway Node (Public) >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo cd /d "%%~dp0" >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo set GATEWAY_AUTO_PUBLIC=true >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo echo Starting Autho Gateway in PUBLIC mode... >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo echo. >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo echo Your gateway will be accessible from the internet! >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo echo. >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo node gateway-package.js >> "%INSTALL_DIR%\Start Gateway (Public).bat"
echo pause >> "%INSTALL_DIR%\Start Gateway (Public).bat"

:: Create desktop shortcuts with Autho icon
set DESKTOP=%USERPROFILE%\Desktop
set ICON=%INSTALL_DIR%\autho.ico

:: Private Gateway shortcut
powershell -Command "& {$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Autho Gateway.lnk'); $s.TargetPath = '%INSTALL_DIR%\Start Gateway.bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'Start Autho Gateway (Private Mode)'; $s.IconLocation = '%ICON%,0'; $s.Save()}"

:: Public Gateway shortcut
powershell -Command "& {$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Autho Gateway (Public).lnk'); $s.TargetPath = '%INSTALL_DIR%\Start Gateway (Public).bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'Start Autho Gateway (Public Mode - Share with the world)'; $s.IconLocation = '%ICON%,0'; $s.Save()}"

:: Open Autho in Browser shortcut
powershell -Command "& {$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Open Autho.lnk'); $s.TargetPath = 'http://localhost:3001'; $s.Description = 'Open Autho Gateway in your browser'; $s.IconLocation = '%ICON%,0'; $s.Save()}"

echo  [OK] Desktop shortcuts created with Autho icon

echo.
echo  ========================================
echo     INSTALLATION COMPLETE!
echo  ========================================
echo.
echo  Three shortcuts have been added to your desktop:
echo.
echo    [Autho Gateway]          - Run locally on your PC
echo    [Autho Gateway (Public)] - Share with the world
echo    [Open Autho]             - Open in your browser
echo.
echo  Would you like to start the gateway now?
echo.
choice /C YN /M "Start Autho Gateway"
if %ERRORLEVEL% EQU 1 (
    echo.
    echo  Starting Autho Gateway...
    start "" "%INSTALL_DIR%\Start Gateway.bat"
    timeout /t 3 /nobreak >nul
    start http://localhost:3001
)

echo.
echo  Installation folder: %INSTALL_DIR%
echo  Local URL: http://localhost:3001
echo.
echo  Press any key to exit...
pause >nul
