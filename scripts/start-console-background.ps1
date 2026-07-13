param(
  [string]$HostName = "127.0.0.1",
  [int]$Port = 8787,
  [string]$StdoutPath = "",
  [string]$StderrPath = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Resolve-OutputPath([string]$Path, [string]$DefaultName) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    return Join-Path $Root $DefaultName
  }
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }
  return Join-Path $Root $Path
}

Set-Location $Root
$env:PYTHONIOENCODING = "utf-8"

$stdout = Resolve-OutputPath $StdoutPath "server.out.log"
$stderr = Resolve-OutputPath $StderrPath "server.err.log"
$python = "python.exe"

$arguments = @(
  "app.py",
  "--host",
  $HostName,
  "--port",
  [string]$Port
)

$proc = Start-Process `
  -FilePath $python `
  -ArgumentList $arguments `
  -WorkingDirectory $Root `
  -WindowStyle Hidden `
  -RedirectStandardOutput $stdout `
  -RedirectStandardError $stderr `
  -PassThru

Write-Host "Local console started in background: PID $($proc.Id)"
