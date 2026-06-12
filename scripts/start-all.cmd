@echo off
setlocal
cd /d "%~dp0.."

call scripts\start-prometheus.cmd

for /l %%i in (1,1,30) do (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $c = Get-NetTCPConnection -LocalPort 8787 -ErrorAction Stop; if ($c) { exit 0 } } catch { exit 1 }"
  if %ERRORLEVEL% EQU 0 exit /b 0
  timeout /t 2 /nobreak >nul
)

start "Local Monitor Console" /min scripts\start-console.cmd
