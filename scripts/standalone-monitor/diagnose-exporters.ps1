param(
  [string]$Root = "E:\ops-monitor",
  [string]$Name = "",
  [string]$IP = "",
  [switch]$Json
)

$ErrorActionPreference = "Stop"

$TargetsFile = Join-Path $Root "config\targets.local.json"
$TunnelsFile = Join-Path $Root "config\tunnels.local.json"

if (-not (Test-Path -LiteralPath $TargetsFile)) {
  throw "Missing target inventory: $TargetsFile"
}

function Test-PortFast($HostName, $Port, $TimeoutMs = 1500) {
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

function Get-SuggestedCommands($OS, $MetricsPort, $TunnelLocalPort) {
  if ($TunnelLocalPort) {
    return @(
      "Get-NetTCPConnection -LocalPort $TunnelLocalPort",
      "Invoke-WebRequest -UseBasicParsing http://127.0.0.1:$TunnelLocalPort/metrics"
    )
  }

  if ($OS -eq "windows") {
    return @(
      "Get-Service windows_exporter",
      "Get-NetTCPConnection -LocalPort $MetricsPort",
      "Invoke-WebRequest -UseBasicParsing http://127.0.0.1:$MetricsPort/metrics"
    )
  }

  return @(
    "systemctl status node_exporter",
    "ss -ltnp | grep ':$MetricsPort'",
    "curl -fsS http://127.0.0.1:$MetricsPort/metrics >/dev/null"
  )
}

function Get-Diagnosis($OS, $SshOpen, $MetricsOpen, $TunnelOpen) {
  if ($MetricsOpen) {
    return "metrics_open"
  }
  if ($TunnelOpen) {
    return "covered_by_ssh_tunnel"
  }
  if ($OS -eq "windows") {
    return "windows_exporter_unreachable"
  }
  if ($SshOpen) {
    return "node_exporter_unreachable"
  }
  return "host_or_management_port_unreachable"
}

$inventory = Get-Content -Raw -Encoding UTF8 -LiteralPath $TargetsFile | ConvertFrom-Json
$tunnels = @()
if (Test-Path -LiteralPath $TunnelsFile) {
  $tunnelInventory = Get-Content -Raw -Encoding UTF8 -LiteralPath $TunnelsFile | ConvertFrom-Json
  $tunnels = @($tunnelInventory.tunnels | Where-Object { $_.enabled -ne $false })
}
$servers = @($inventory.servers)
if ($Name) {
  $servers = @($servers | Where-Object { $_.name -eq $Name })
}
if ($IP) {
  $servers = @($servers | Where-Object { $_.ip -eq $IP })
}

$results = foreach ($server in $servers) {
  $os = [string]$server.os
  $metricsPort = if ($os -eq "windows") { 9182 } else { 9100 }
  $managementOpen = Test-PortFast $server.ip 22
  $metricsOpen = Test-PortFast $server.ip $metricsPort
  $tunnel = @(
    $tunnels | Where-Object {
      $_.sshHost -eq $server.ip -and [int]$_.remotePort -eq $metricsPort
    } | Select-Object -First 1
  )
  $tunnelItem = if ($tunnel.Count -gt 0) { $tunnel[0] } else { $null }
  $tunnelLocalHost = if ($tunnelItem -and $tunnelItem.localHost) { [string]$tunnelItem.localHost } else { "127.0.0.1" }
  $tunnelLocalPort = if ($tunnelItem) { [int]$tunnelItem.localPort } else { $null }
  $tunnelOpen = if ($tunnelItem) { Test-PortFast $tunnelLocalHost $tunnelLocalPort } else { $false }
  [pscustomobject]@{
    Name = [string]$server.name
    IP = [string]$server.ip
    OS = $os
    Role = [string]$server.role
    ManagementPortOpen = $managementOpen
    MetricsPort = $metricsPort
    MetricsOpen = $metricsOpen
    TunnelName = if ($tunnelItem) { [string]$tunnelItem.name } else { "" }
    TunnelLocalPort = $tunnelLocalPort
    TunnelOpen = $tunnelOpen
    Diagnosis = Get-Diagnosis $os $managementOpen $metricsOpen $tunnelOpen
    SuggestedCommands = @(Get-SuggestedCommands $os $metricsPort $tunnelLocalPort)
  }
}

if ($Json) {
  @($results) | ConvertTo-Json -Depth 5
  exit 0
}

if (-not $results -or @($results).Count -eq 0) {
  Write-Host "No matching targets."
  exit 0
}

@($results) | Select-Object Name,IP,OS,MetricsPort,ManagementPortOpen,MetricsOpen,TunnelLocalPort,TunnelOpen,Diagnosis | Format-Table -AutoSize
Write-Host ""
foreach ($item in @($results)) {
  if ($item.MetricsOpen -or $item.Diagnosis -eq "covered_by_ssh_tunnel") {
    continue
  }
  Write-Host "Suggested read-only checks for $($item.Name):"
  foreach ($command in $item.SuggestedCommands) {
    Write-Host "  $command"
  }
}
