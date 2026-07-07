param(
  [string]$Root = "E:\ops-monitor"
)

$ErrorActionPreference = "Stop"

$Run = Join-Path $Root "run"
$PidFile = Join-Path $Run "ssh_metrics_tunnel.pid"
$ScriptPath = Join-Path $Root "scripts\ssh_metrics_tunnel.py"

function Get-ProcessCommandLine($ProcessId) {
  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
  if ($proc) {
    return [string]$proc.CommandLine
  }
  return ""
}

if (-not (Test-Path $PidFile)) {
  Write-Host "ssh_metrics_tunnel: no pid file"
  exit 0
}

$pidValue = [int](Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue)
$commandLine = Get-ProcessCommandLine $pidValue
if (-not $commandLine) {
  Write-Host "ssh_metrics_tunnel: not running"
  Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
  exit 0
}
if (-not $commandLine.Contains($Root) -or -not $commandLine.Contains("ssh_metrics_tunnel.py")) {
  Write-Host "ssh_metrics_tunnel: PID $pidValue is not owned by $Root, skipped"
  exit 1
}

Stop-Process -Id $pidValue -Force
Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
Write-Host "ssh_metrics_tunnel: stopped PID $pidValue"
