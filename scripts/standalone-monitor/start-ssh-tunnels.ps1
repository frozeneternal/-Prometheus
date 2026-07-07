param(
  [string]$Root = "E:\ops-monitor"
)

$ErrorActionPreference = "Stop"

$ConfigPath = Join-Path $Root "config\tunnels.local.json"
$ScriptPath = Join-Path $Root "scripts\ssh_metrics_tunnel.py"
$Run = Join-Path $Root "run"
$Logs = Join-Path $Root "logs"
$PidFile = Join-Path $Run "ssh_metrics_tunnel.pid"

New-Item -ItemType Directory -Force -Path $Run, $Logs | Out-Null

if (-not (Test-Path $ConfigPath)) {
  throw "Missing tunnel config: $ConfigPath"
}
if (-not (Test-Path $ScriptPath)) {
  throw "Missing tunnel script: $ScriptPath"
}
if (-not $env:OPS_SSH_USER -or -not $env:OPS_SSH_PASSWORD) {
  throw "OPS_SSH_USER and OPS_SSH_PASSWORD must be set before starting tunnels."
}

function Get-ProcessCommandLine($ProcessId) {
  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
  if ($proc) {
    return [string]$proc.CommandLine
  }
  return ""
}

if (Test-Path $PidFile) {
  $oldPid = [int](Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue)
  $oldCommandLine = Get-ProcessCommandLine $oldPid
  if ($oldCommandLine -and $oldCommandLine.Contains($ScriptPath)) {
    Write-Host "ssh_metrics_tunnel already running: PID $oldPid"
    exit 0
  }
}

$stdout = Join-Path $Logs "ssh_metrics_tunnel.out.log"
$stderr = Join-Path $Logs "ssh_metrics_tunnel.err.log"
$proc = Start-Process -FilePath "python" -ArgumentList @($ScriptPath, "--config", $ConfigPath) -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
Set-Content -LiteralPath $PidFile -Value $proc.Id -Encoding ASCII
Write-Host "ssh_metrics_tunnel started: PID $($proc.Id)"
