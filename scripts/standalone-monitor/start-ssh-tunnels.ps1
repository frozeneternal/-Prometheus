param(
  [string]$Root = "E:\ops-monitor",
  [switch]$Restart
)

$ErrorActionPreference = "Stop"

$ConfigPath = Join-Path $Root "config\tunnels.local.json"
$ScriptPath = Join-Path $Root "scripts\ssh_metrics_tunnel.py"
$Run = Join-Path $Root "run"
$Logs = Join-Path $Root "logs"
$PidFile = Join-Path $Run "ssh_metrics_tunnel.pid"
$CredentialFile = Join-Path $Root "config\ssh-credential.local.xml"

New-Item -ItemType Directory -Force -Path $Run, $Logs | Out-Null

if (-not (Test-Path $ConfigPath)) {
  throw "Missing tunnel config: $ConfigPath"
}
if (-not (Test-Path $ScriptPath)) {
  throw "Missing tunnel script: $ScriptPath"
}
if ((-not $env:OPS_SSH_USER -or -not $env:OPS_SSH_PASSWORD) -and (Test-Path $CredentialFile)) {
  $credential = Import-Clixml -LiteralPath $CredentialFile
  $env:OPS_SSH_USER = $credential.UserName
  $env:OPS_SSH_PASSWORD = $credential.GetNetworkCredential().Password
}
if (-not $env:OPS_SSH_USER -or -not $env:OPS_SSH_PASSWORD) {
  throw "OPS_SSH_USER and OPS_SSH_PASSWORD must be set, or $CredentialFile must exist."
}

function Get-ProcessCommandLine($ProcessId) {
  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
  if ($proc) {
    return [string]$proc.CommandLine
  }
  return ""
}

function Get-TunnelProcessId($ScriptPath) {
  $escapedPath = [string]$ScriptPath
  $processes = @(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object {
        $_.Name -match '^python(\.exe)?$' -and
        $_.CommandLine -and
        ([string]$_.CommandLine).Contains($escapedPath)
      }
  )
  if ($processes.Count -gt 0) {
    return $processes[0].ProcessId
  }
  return $null
}

function Quote-CmdArgument([string]$Value) {
  return '"' + $Value.Replace('"', '""') + '"'
}

function ConvertTo-LoggedCommand($FilePath, [string[]]$ArgumentList, $StdoutPath, $StderrPath) {
  $parts = @((Quote-CmdArgument $FilePath))
  foreach ($argument in $ArgumentList) {
    $parts += Quote-CmdArgument ([string]$argument)
  }
  return (($parts -join " ") + " 1>> " + (Quote-CmdArgument $StdoutPath) + " 2>> " + (Quote-CmdArgument $StderrPath))
}

function Start-NoWindowLoggedCommand($FilePath, [string[]]$ArgumentList, $WorkingDirectory, $StdoutPath, $StderrPath) {
  $command = ConvertTo-LoggedCommand $FilePath $ArgumentList $StdoutPath $StderrPath
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = "cmd.exe"
  $psi.Arguments = "/d /c `"$command`""
  $psi.WorkingDirectory = $WorkingDirectory
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

  $proc = [System.Diagnostics.Process]::new()
  $proc.StartInfo = $psi
  [void]$proc.Start()
  return $proc
}

if (Test-Path $PidFile) {
  $oldPid = [int](Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue)
  $oldCommandLine = Get-ProcessCommandLine $oldPid
  if ($oldCommandLine -and $oldCommandLine.Contains($ScriptPath)) {
    if ($Restart) {
      Stop-Process -Id $oldPid -Force
      Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
      Write-Host "ssh_metrics_tunnel restarted old PID $oldPid"
    } else {
      Write-Host "ssh_metrics_tunnel already running: PID $oldPid"
      exit 0
    }
  } elseif ($oldCommandLine) {
    throw "PID $oldPid is not owned by $ScriptPath"
  } else {
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
  }
}

$stdout = Join-Path $Logs "ssh_metrics_tunnel.out.log"
$stderr = Join-Path $Logs "ssh_metrics_tunnel.err.log"
$launcher = Start-NoWindowLoggedCommand `
  -FilePath "python" `
  -ArgumentList @($ScriptPath, "--config", $ConfigPath) `
  -WorkingDirectory $Root `
  -StdoutPath $stdout `
  -StderrPath $stderr

$tunnelPid = $null
for ($i = 0; $i -lt 20; $i++) {
  Start-Sleep -Milliseconds 250
  $tunnelPid = Get-TunnelProcessId $ScriptPath
  if ($tunnelPid) {
    break
  }
}

if (-not $tunnelPid) {
  Stop-Process -Id $launcher.Id -Force -ErrorAction SilentlyContinue
  throw "ssh_metrics_tunnel launch wrapper started, but no python tunnel process was found. See $stderr"
}

Set-Content -LiteralPath $PidFile -Value $tunnelPid -Encoding ASCII
Write-Host "ssh_metrics_tunnel started: PID $tunnelPid"
