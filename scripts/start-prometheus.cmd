@echo off
setlocal
cd /d "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wait-docker.ps1"
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
where docker-compose >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  docker-compose -p localmonitor up -d
) else (
  docker compose -p localmonitor up -d
)
