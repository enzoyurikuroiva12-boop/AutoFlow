@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 goto no_node
where npm >nul 2>nul
if errorlevel 1 goto no_npm

node -e "const [major,minor]=process.versions.node.split('.').map(Number);process.exit(major>22||(major===22&&minor>=13)?0:1)"
if errorlevel 1 goto old_node

if not exist ".env" (
  copy /Y ".env.example" ".env" >nul
  if errorlevel 1 goto env_failed
  echo Created .env with the local SQLite defaults.
)

echo Downloading and installing project dependencies with npm ci...
call npm.cmd ci
if errorlevel 1 goto install_failed

echo.
echo AutoFlow dependencies are ready. Run iniciar.bat to start the app.
if /i "%~1"=="/quiet" exit /b 0
pause
exit /b 0

:no_node
echo Node.js 22.13 or newer is required. Install the current LTS release:
echo https://nodejs.org/
goto failed

:no_npm
echo npm was not found. Reinstall Node.js with npm enabled.
goto failed

:old_node
echo Node.js 22.13 or newer is required. Current version:
node --version
goto failed

:env_failed
echo Could not create .env from .env.example.
goto failed

:install_failed
echo Dependency installation failed. Check your network and try again.

:failed
pause
exit /b 1
