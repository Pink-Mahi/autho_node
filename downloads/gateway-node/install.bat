@echo off
REM Autho Gateway Node Installation Script
REM For Windows

echo 🌐 Autho Gateway Node Installation
echo ==================================

REM Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ first.
    echo    Visit: https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js found
node --version

REM Check Node.js version
for /f "tokens=1 delims=." %%i in ('node -e "process.stdout.write(process.versions.node.split('')[0]"')') do set NODE_VERSION=%%i
if %NODE_VERSION% LSS 18 (
    echo ❌ Node.js version must be 18 or higher.
    node --version
    pause
    exit /b 1
)

echo ✅ Node.js version is compatible

REM Create installation directory
set INSTALL_DIR=%USERPROFILE%\autho-gateway-node
echo 📁 Creating installation directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
cd /d "%INSTALL_DIR%"

REM Download the latest release
echo 📥 Downloading Autho Gateway Node...
if exist curl.exe (
    curl -L https://github.com/Pink-Mahi/autho/archive/main.tar.gz -o autho-gateway.tar.gz
) else if exist wget.exe (
    wget https://github.com/Pink-Mahi/autho/archive/main.tar.gz -O autho-gateway.tar.gz
) else (
    echo ❌ Neither curl nor wget found. Please install one of them.
    pause
    exit /b 1
)

REM Extract the archive
echo 📦 Extracting archive...
tar -xzf autho-gateway.tar.gz
cd autho-main

REM Install dependencies
echo 📦 Installing dependencies...
npm install

REM Build the project
echo 🔨 Building the project...
npm run build

REM --- Auto-setup TURN (coturn) + secret ---
if not exist "gateway-data" mkdir "gateway-data"
for /f "delims=" %%s in ('powershell -NoProfile -Command "[Guid]::NewGuid().ToString('N')"') do set TURN_SECRET=%%s
(
echo {"username":"autho","credential":"%TURN_SECRET%"}
) > gateway-data\turn.json

where docker >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo 🧩 Starting coturn via Docker...
    docker rm -f autho-turn >nul 2>&1
    docker run -d --name autho-turn --restart unless-stopped -p 3478:3478/tcp -p 3478:3478/udp -p 49152-49200:49152-49200/udp instrumentisto/coturn -n --log-file=stdout --use-auth-secret --static-auth-secret=%TURN_SECRET% --realm=autho --min-port=49152 --max-port=49200 >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo ✅ coturn running (Docker)
    ) else (
        echo ⚠️  Could not start coturn via Docker
    )
) else (
    echo ⚠️  Docker not found. Install Docker Desktop or use WSL for TURN.
)

REM Create configuration file
echo ⚙️ Creating configuration...
(
echo {
echo   "nodeId": "gateway-%RANDOM%",
echo   "port": 3001,
echo   "host": "0.0.0.0",
echo   "seedNodes": ["autho.pinkmahi.com:3000", "autho.cartpathcleaning.com"],
echo   "dataDir": "./gateway-data",
echo   "cache": {
echo     "enabled": true,
echo     "ttl": 300000
echo   },
echo   "rateLimit": {
echo     "enabled": true,
echo     "window": 60000,
echo     "max": 100
echo   }
echo }
) > gateway-config.json

REM Create startup script
echo 🚀 Creating startup script...
(
echo @echo off
echo cd /d "%%~dp0"
echo node dist/gateway/gateway-node.js --config=gateway-config.json
) > start-gateway.bat

REM Create Windows service
echo 🔧 Creating Windows service...
sc create "AuthoGateway" binPath= "%INSTALL_DIR%\autho-main\start-gateway.bat" start= auto
sc description "Autho Gateway Node Service"
echo ✅ Windows service created

REM Cleanup
echo 🧹 Cleaning up...
cd ..
del /f autho-gateway.tar.gz

echo.
echo ✅ Installation complete!
echo.
echo 🚀 To start the gateway node:
echo    cd "%INSTALL_DIR%\autho-main"
echo    start-gateway.bat
echo.
echo 🌐 Gateway node will be available at:
echo    http://localhost:3001
echo.
echo 📊 Check status:
echo    curl http://localhost:3001/health
echo.
echo 📖 For more information, see:
echo    %INSTALL_DIR%\autho-main\downloads\gateway-node\README.md
echo.
echo 🎉 Welcome to the Autho network!
echo.
pause
