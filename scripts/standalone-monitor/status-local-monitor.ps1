$ErrorActionPreference = "Continue"

param(
  [string]$Root = "E:\ops-monitor"
)

$TargetsFile = Join-Path $Root "config\targets.local.json"

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

function Get-HttpStatus($Url) {
  try {
    return (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3).StatusCode
  } catch {
    return "ERR"
  }
}

$local = @(
  [pscustomobject]@{Name="Grafana"; Url="http://127.0.0.1:3000/api/health"; Status=Get-HttpStatus "http://127.0.0.1:3000/api/health"},
  [pscustomobject]@{Name="Prometheus"; Url="http://127.0.0.1:19090/-/ready"; Status=Get-HttpStatus "http://127.0.0.1:19090/-/ready"},
  [pscustomobject]@{Name="Windows exporter"; Url="http://127.0.0.1:9182/metrics"; Status=Get-HttpStatus "http://127.0.0.1:9182/metrics"}
)

Write-Host "Local stack"
$local | Format-Table -AutoSize

if (Test-Path $TargetsFile) {
  $inventory = Get-Content -Raw -Encoding UTF8 -LiteralPath $TargetsFile | ConvertFrom-Json
  $remote = foreach ($server in $inventory.servers) {
    $metricsPort = if ($server.os -eq "windows") { 9182 } else { 9100 }
    [pscustomobject]@{
      Name = $server.name
      IP = $server.ip
      OS = $server.os
      SSH22 = Test-PortFast $server.ip 22
      MetricsPort = $metricsPort
      MetricsOpen = Test-PortFast $server.ip $metricsPort
    }
  }
  Write-Host ""
  Write-Host "Remote targets"
  $remote | Format-Table -AutoSize
}

try {
  $targets = Invoke-RestMethod -Uri "http://127.0.0.1:19090/api/v1/targets" -TimeoutSec 5
  $active = $targets.data.activeTargets | ForEach-Object {
    [pscustomobject]@{
      Job = $_.labels.job
      Instance = $_.labels.instance
      Name = $_.labels.name
      Health = $_.health
      LastError = $_.lastError
    }
  }
  Write-Host ""
  Write-Host "Prometheus targets"
  $active | Format-Table -AutoSize
} catch {
  Write-Host ""
  Write-Host "Prometheus targets unavailable: $($_.Exception.Message)"
}
