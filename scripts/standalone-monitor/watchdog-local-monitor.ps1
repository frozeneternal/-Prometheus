param(
  [string]$Root = "E:\ops-monitor"
)

$ErrorActionPreference = "Continue"

$Config = Join-Path $Root "config"
$Logs = Join-Path $Root "logs"
$WatchdogLog = Join-Path $Logs "watchdog-local-monitor.log"
$StartLocal = Join-Path $Root "scripts\start-local-monitor.ps1"
$StartTunnels = Join-Path $Root "scripts\start-ssh-tunnels.ps1"
$TunnelsConfig = Join-Path $Config "tunnels.local.json"

New-Item -ItemType Directory -Force -Path $Logs | Out-Null

function Write-WatchdogLog($Message) {
  $line = "$(Get-Date -Format o) $Message"
  Add-Content -LiteralPath $WatchdogLog -Value $line -Encoding UTF8
  Write-Host $line
}

function Get-HttpStatus($Url) {
  try {
    return (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3).StatusCode
  } catch {
    return "ERR"
  }
}

function Test-PortFast($HostName, $Port, $TimeoutMs = 1000) {
  $client = [System.Net.Sockets.TcpClient]::new()
  try {
    $iar = $client.BeginConnect($HostName, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      return $false
    }
    $client.EndConnect($iar)
    return $true
  } catch {
    return $false
  } finally {
    $client.Close()
  }
}

$localChecks = @(
  @{Name="grafana"; Url="http://127.0.0.1:3000/api/health"},
  @{Name="prometheus"; Url="http://127.0.0.1:19090/-/ready"},
  @{Name="windows_exporter"; Url="http://127.0.0.1:9182/metrics"}
)

$localFailed = @()
foreach ($check in $localChecks) {
  $status = Get-HttpStatus $check.Url
  if ($status -ne 200) {
    $localFailed += "$($check.Name)=$status"
  }
}

if ($localFailed.Count -gt 0) {
  Write-WatchdogLog "local stack unhealthy: $($localFailed -join ', '); running start-local-monitor.ps1"
  powershell -ExecutionPolicy Bypass -File $StartLocal -Root $Root | ForEach-Object { Write-WatchdogLog $_ }
} else {
  Write-WatchdogLog "local stack healthy"
}

if (Test-Path $TunnelsConfig) {
  try {
    $inventory = Get-Content -Raw -Encoding UTF8 -LiteralPath $TunnelsConfig | ConvertFrom-Json
    $closed = @()
    foreach ($tunnel in $inventory.tunnels) {
      if ($tunnel.enabled -eq $false) {
        continue
      }
      $localHost = "127.0.0.1"
      if ($tunnel.localHost) {
        $localHost = [string]$tunnel.localHost
      }
      $localPort = [int]$tunnel.localPort
      if (-not (Test-PortFast $localHost $localPort)) {
        $closed += "$($tunnel.name)=$localHost`:$localPort"
      }
    }
    if ($closed.Count -gt 0) {
      if ($env:OPS_SSH_USER -and $env:OPS_SSH_PASSWORD) {
        Write-WatchdogLog "ssh tunnel listeners unhealthy: $($closed -join ', '); running start-ssh-tunnels.ps1"
        powershell -ExecutionPolicy Bypass -File $StartTunnels -Root $Root | ForEach-Object { Write-WatchdogLog $_ }
      } else {
        Write-WatchdogLog "ssh tunnel listeners unhealthy but OPS_SSH_USER/OPS_SSH_PASSWORD are not set: $($closed -join ', ')"
      }
    } else {
      Write-WatchdogLog "ssh tunnel listeners healthy"
    }
  } catch {
    Write-WatchdogLog "failed to inspect ssh tunnel config: $($_.Exception.Message)"
  }
}
