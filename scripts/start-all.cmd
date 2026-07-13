@echo off
setlocal
cd /d "%~dp0.."
set PYTHONIOENCODING=utf-8

call scripts\start-prometheus.cmd

for /l %%i in (1,1,30) do (
  powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "try { $c = Get-NetTCPConnection -LocalPort 8787 -ErrorAction Stop; if ($c) { exit 0 } } catch { exit 1 }"
  if %ERRORLEVEL% EQU 0 exit /b 0
  timeout /t 2 /nobreak >nul
)

start "" /b cmd /c "python app.py --host 127.0.0.1 --port 8787 > server.out.log 2> server.err.log"
