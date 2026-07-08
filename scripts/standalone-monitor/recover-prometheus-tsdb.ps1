param(
  [string]$Root = "E:\ops-monitor",
  [switch]$StartAfterRecovery,
  [switch]$Force
)

$ErrorActionPreference = "Stop"

function Resolve-FullPath($Path) {
  return [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
}

function Assert-PathUnderRoot($Path, $RootPath) {
  $fullPath = Resolve-FullPath $Path
  $fullRoot = Resolve-FullPath $RootPath
  $comparison = [System.StringComparison]::OrdinalIgnoreCase
  if ($fullPath.Equals($fullRoot, $comparison) -or $fullPath.StartsWith("$fullRoot\", $comparison)) {
    return $fullPath
  }
  throw "Refusing to operate outside root. Path=$fullPath Root=$fullRoot"
}

function Get-ProcessPath($ProcessId) {
  try {
    return (Get-Process -Id $ProcessId -ErrorAction Stop).Path
  } catch {
    return ""
  }
}

function Read-TextOrEmpty($Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
  if ($null -eq $text) {
    return ""
  }
  return $text
}

function Test-PrometheusReady {
  try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:19090/-/ready" -UseBasicParsing -TimeoutSec 5
    return $response.StatusCode -eq 200
  } catch {
    return $false
  }
}

function Test-CorruptionSignature($Text) {
  $patterns = @(
    "fatal error: fault",
    "checkCRC32",
    "Encountered WAL read error",
    "corruption in segment",
    "unexpected fault address"
  )
  foreach ($pattern in $patterns) {
    if ($Text.Contains($pattern)) {
      return $true
    }
  }
  return $false
}

function Stop-RootOwnedPrometheus($PidFile, $RootPath) {
  if (-not (Test-Path -LiteralPath $PidFile)) {
    return
  }
  $pidValue = [int](Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue)
  if (-not $pidValue) {
    return
  }
  $processPath = Get-ProcessPath $pidValue
  if (-not $processPath) {
    return
  }
  Assert-PathUnderRoot $processPath $RootPath | Out-Null
  Stop-Process -Id $pidValue -Force
}

function New-QuarantinePath($DataRoot) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $candidate = Join-Path $DataRoot "prometheus-corrupt-$stamp"
  $index = 1
  while (Test-Path -LiteralPath $candidate) {
    $candidate = Join-Path $DataRoot "prometheus-corrupt-$stamp-$index"
    $index += 1
  }
  return $candidate
}

$Root = Resolve-FullPath $Root
$Config = Assert-PathUnderRoot (Join-Path $Root "config") $Root
$Data = Assert-PathUnderRoot (Join-Path $Root "data") $Root
$Logs = Assert-PathUnderRoot (Join-Path $Root "logs") $Root
$Run = Assert-PathUnderRoot (Join-Path $Root "run") $Root
$PrometheusData = Assert-PathUnderRoot (Join-Path $Data "prometheus") $Root
$PrometheusPid = Assert-PathUnderRoot (Join-Path $Run "prometheus.pid") $Root
$PrometheusErr = Assert-PathUnderRoot (Join-Path $Logs "prometheus.err.log") $Root

New-Item -ItemType Directory -Force -Path $Config, $Data, $Logs, $Run | Out-Null

if ((Test-PrometheusReady) -and -not $Force) {
  Write-Host "Prometheus is already ready on http://127.0.0.1:19090; no recovery needed."
  return
}

$errorLog = Read-TextOrEmpty $PrometheusErr
if (-not $Force -and -not (Test-CorruptionSignature $errorLog)) {
  throw "Prometheus is not ready, but no known TSDB corruption signature was found. Use -Force only after manual review."
}

Stop-RootOwnedPrometheus $PrometheusPid $Root

if (Test-Path -LiteralPath $PrometheusData) {
  $quarantinePath = Assert-PathUnderRoot (New-QuarantinePath $Data) $Root
  Move-Item -LiteralPath $PrometheusData -Destination $quarantinePath
  Write-Host "Quarantined Prometheus TSDB: $quarantinePath"
} else {
  Write-Host "Prometheus TSDB directory is missing; creating a fresh directory."
}

New-Item -ItemType Directory -Force -Path $PrometheusData | Out-Null
Remove-Item -LiteralPath $PrometheusPid -ErrorAction SilentlyContinue

if ($StartAfterRecovery) {
  $startScript = Join-Path $PSScriptRoot "start-local-monitor.ps1"
  if (-not (Test-Path -LiteralPath $startScript)) {
    throw "Cannot find start script: $startScript"
  }
  & $startScript -Root $Root
}
