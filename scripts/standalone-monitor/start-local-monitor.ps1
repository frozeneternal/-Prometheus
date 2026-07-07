param(
  [string]$Root = "E:\ops-monitor"
)

$ErrorActionPreference = "Stop"

$Config = Join-Path $Root "config"
$Apps = Join-Path $Root "apps"
$Data = Join-Path $Root "data"
$Logs = Join-Path $Root "logs"
$Run = Join-Path $Root "run"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

New-Item -ItemType Directory -Force -Path $Config, $Data, $Logs, $Run, (Join-Path $Data "prometheus"), (Join-Path $Data "grafana"), (Join-Path $Logs "grafana") | Out-Null

function Ensure-SecretFile($Path, $Bytes) {
  if (Test-Path $Path) {
    return
  }
  $buffer = [byte[]]::new($Bytes)
  $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
  try {
    $rng.GetBytes($buffer)
  } finally {
    $rng.Dispose()
  }
  $secret = [Convert]::ToBase64String($buffer).TrimEnd("=") -replace "[+/]", "x"
  Set-Content -LiteralPath $Path -Value $secret -NoNewline -Encoding ASCII
}

function Get-ProcessPath($ProcessId) {
  try {
    return (Get-Process -Id $ProcessId -ErrorAction Stop).Path
  } catch {
    return ""
  }
}

function Assert-PortFreeOrOwned($Port, $ExpectedRoot) {
  $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
  foreach ($listener in $listeners) {
    $path = Get-ProcessPath $listener.OwningProcess
    if ($path -and $path.StartsWith($ExpectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
    throw "Port $Port is already used by PID $($listener.OwningProcess) at $path"
  }
  return $false
}

function Get-RootOwnedPortPid($Port, $ExpectedRoot) {
  $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
  foreach ($listener in $listeners) {
    $path = Get-ProcessPath $listener.OwningProcess
    if ($path -and $path.StartsWith($ExpectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $listener.OwningProcess
    }
  }
  return $null
}

function Start-ManagedProcess($Name, $FilePath, $ArgumentList, $WorkingDirectory, $Port) {
  $pidFile = Join-Path $Run "$Name.pid"
  if (Test-Path $pidFile) {
    $oldPid = [int](Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue)
    $oldPath = Get-ProcessPath $oldPid
    if ($oldPath -and $oldPath.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
      Write-Host "$Name already running: PID $oldPid"
      return
    }
  }

  if (Assert-PortFreeOrOwned $Port $Root) {
    $ownedPid = Get-RootOwnedPortPid $Port $Root
    if ($ownedPid) {
      Set-Content -LiteralPath $pidFile -Value $ownedPid -Encoding ASCII
      Write-Host "$Name already listening on ${Port}: PID $ownedPid"
    } else {
      Write-Host "$Name port $Port already owned by this stack"
    }
    return
  }

  $stdout = Join-Path $Logs "$Name.out.log"
  $stderr = Join-Path $Logs "$Name.err.log"
  $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
  Set-Content -LiteralPath $pidFile -Value $proc.Id -Encoding ASCII
  Write-Host "$Name started: PID $($proc.Id)"
}

function Ensure-GrafanaProvisioning {
  $provisioning = Join-Path $Config "grafana-provisioning"
  $datasources = Join-Path $provisioning "datasources"
  $dashboardProviders = Join-Path $provisioning "dashboards"
  $plugins = Join-Path $provisioning "plugins"
  $alerting = Join-Path $provisioning "alerting"
  $dashboards = Join-Path $Config "grafana-dashboards"
  New-Item -ItemType Directory -Force -Path $datasources, $dashboardProviders, $plugins, $alerting, $dashboards | Out-Null

  @"
apiVersion: 1

datasources:
  - name: Local Prometheus
    uid: local-prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:19090
    isDefault: true
    editable: true
"@ | Set-Content -LiteralPath (Join-Path $datasources "prometheus.yml") -Encoding UTF8

  @"
apiVersion: 1

providers:
  - name: Local Ops Dashboards
    orgId: 1
    folder: Local Ops
    type: file
    disableDeletion: false
    allowUiUpdates: true
    options:
      path: $dashboards
"@ | Set-Content -LiteralPath (Join-Path $dashboardProviders "local.yml") -Encoding UTF8

  $dashboardTemplate = Join-Path $ScriptRoot "ops-overview.dashboard.json"
  if (Test-Path $dashboardTemplate) {
    Copy-Item -LiteralPath $dashboardTemplate -Destination (Join-Path $dashboards "ops-overview.json") -Force
  }
}

Ensure-SecretFile (Join-Path $Config "grafana-admin-password.txt") 18
Ensure-SecretFile (Join-Path $Config "grafana-secret-key.txt") 32
Ensure-GrafanaProvisioning

Start-ManagedProcess `
  -Name "windows_exporter" `
  -FilePath (Join-Path $Apps "windows_exporter\windows_exporter.exe") `
  -ArgumentList @("--web.listen-address=127.0.0.1:9182") `
  -WorkingDirectory (Join-Path $Apps "windows_exporter") `
  -Port 9182

Start-ManagedProcess `
  -Name "prometheus" `
  -FilePath (Join-Path $Apps "prometheus\prometheus.exe") `
  -ArgumentList @(
    "--config.file=$(Join-Path $Config 'prometheus.yml')",
    "--storage.tsdb.path=$(Join-Path $Data 'prometheus')",
    "--web.listen-address=127.0.0.1:19090",
    "--web.enable-lifecycle"
  ) `
  -WorkingDirectory (Join-Path $Apps "prometheus") `
  -Port 19090

Start-ManagedProcess `
  -Name "grafana" `
  -FilePath (Join-Path $Apps "grafana\bin\grafana.exe") `
  -ArgumentList @("server", "--config=$(Join-Path $Config 'grafana-custom.ini')", "--homepath=$(Join-Path $Apps 'grafana')") `
  -WorkingDirectory (Join-Path $Apps "grafana") `
  -Port 3000

Write-Host "Prometheus: http://127.0.0.1:19090"
Write-Host "Grafana:    http://127.0.0.1:3000"
Write-Host "Grafana admin password file: $(Join-Path $Config 'grafana-admin-password.txt')"
