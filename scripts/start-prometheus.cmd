@echo off
setlocal
cd /d "%~dp0.."
set "HIDDEN_LAUNCHER=%~dp0run-hidden.vbs"
if not exist "%HIDDEN_LAUNCHER%" exit /b 2
wscript.exe //B "%HIDDEN_LAUNCHER%" "powershell.exe" "-NoProfile" "-WindowStyle" "Hidden" "-ExecutionPolicy" "Bypass" "-File" "%~dp0wait-docker.ps1"
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
where docker-compose >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  docker-compose -p localmonitor up -d
) else (
  docker compose -p localmonitor up -d
)
