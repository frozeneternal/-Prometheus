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

function Quote-CmdArgument([string]$Value) {
  return '"' + $Value.Replace('"', '""') + '"'
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

$pythonCommand = (($arguments | ForEach-Object { Quote-CmdArgument $_ }) -join " ")
$command = "$(Quote-CmdArgument $python) $pythonCommand 1>> $(Quote-CmdArgument $stdout) 2>> $(Quote-CmdArgument $stderr)"

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = "cmd.exe"
$psi.Arguments = "/d /c `"$command`""
$psi.WorkingDirectory = $Root
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

$proc = [System.Diagnostics.Process]::Start($psi)

Write-Host "Local console started in background: PID $($proc.Id)"
