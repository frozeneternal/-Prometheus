@echo off
setlocal
cd /d "%~dp0.."
set PYTHONIOENCODING=utf-8
set "HIDDEN_LAUNCHER=%~dp0run-hidden.vbs"
set "CONSOLE_STARTER=%~dp0start-console-background.ps1"
set "SERVER_OUT=%CD%\server.out.log"
set "SERVER_ERR=%CD%\server.err.log"
if not exist "%HIDDEN_LAUNCHER%" exit /b 2
if not exist "%CONSOLE_STARTER%" exit /b 2

call scripts\start-prometheus.cmd

for /l %%i in (1,1,30) do (
  wscript.exe //B "%HIDDEN_LAUNCHER%" "powershell.exe" "-NoProfile" "-WindowStyle" "Hidden" "-ExecutionPolicy" "Bypass" "-Command" "try { $c = Get-NetTCPConnection -LocalPort 8787 -ErrorAction Stop; if ($c) { exit 0 } } catch { exit 1 }"
  if not errorlevel 1 exit /b 0
  timeout /t 2 /nobreak >nul
)

wscript.exe //B "%HIDDEN_LAUNCHER%" "powershell.exe" "-NoProfile" "-WindowStyle" "Hidden" "-ExecutionPolicy" "Bypass" "-File" "%CONSOLE_STARTER%" "-StdoutPath" "%SERVER_OUT%" "-StderrPath" "%SERVER_ERR%"
exit /b %ERRORLEVEL%
