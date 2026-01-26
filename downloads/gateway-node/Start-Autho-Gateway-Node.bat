@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ==============================================
echo  Autho Gateway Node (One-Click Launcher)
echo ==============================================

where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo ERROR: Node.js is not installed.
  echo Please install Node.js 18+ from https://nodejs.org/
  echo.
  pause
  exit /b 1
)

where npm >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo ERROR: npm was not found.
  echo Reinstall Node.js (it includes npm): https://nodejs.org/
  echo.
  pause
  exit /b 1
)

set "PORT=%1"
if "%PORT%"=="" (
  if defined GATEWAY_PORT (
    set "PORT=%GATEWAY_PORT%"
  ) else (
    set "PORT=3001"
  )
)

if not exist "node_modules" (
echo Installing dependencies (first run)...
  call npm install
)

echo.
echo Starting gateway node on port %PORT%...
echo A new window will open with the node logs.
echo.

start "Autho Gateway Node" cmd /k "cd /d \"%SCRIPT_DIR%\" ^&^& set GATEWAY_PORT=%PORT% ^&^& set AUTHO_OPERATOR_URLS=http://autho.pinkmahi.com:3000,https://autho.pinkmahi.com,https://autho.cartpathcleaning.com ^&^& node gateway-package.js"

timeout /t 2 /nobreak >nul
start "" "http://localhost:%PORT%/m"

echo.
echo Opened: http://localhost:%PORT%/m
echo.
echo Tip: You can pass a custom port:
echo   Start-Autho-Gateway-Node.bat 3005
echo.
echo This launcher can be pinned to Start or placed on Desktop.
echo.
exit /b 0
