param(
  [string]$Root = "E:\ops-monitor",
  [int]$MinAgeHours = 24,
  [switch]$DryRun,
  [switch]$ConfirmCleanup,
  [switch]$Json
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

function Test-PrometheusReady {
  try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:19090/-/ready" -UseBasicParsing -TimeoutSec 5
    return $response.StatusCode -eq 200
  } catch {
    return $false
  }
}

function Get-DirectorySizeBytes($Path) {
  try {
    $sum = (
      Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum
    ).Sum
    if ($null -eq $sum) {
      return 0
    }
    return [int64]$sum
  } catch {
    return 0
  }
}

$Root = Resolve-FullPath $Root
$Data = Assert-PathUnderRoot (Join-Path $Root "data") $Root
$minimumAge = [Math]::Max(0, $MinAgeHours)
$cutoff = (Get-Date).AddHours(-$minimumAge)
$isDryRun = (-not $ConfirmCleanup) -or $DryRun

if (-not (Test-Path -LiteralPath $Data)) {
  throw "Data directory does not exist: $Data"
}

if (-not $isDryRun -and -not (Test-PrometheusReady)) {
  throw "Refusing to delete Prometheus quarantines while Prometheus is not ready."
}

$quarantines = @(
  Get-ChildItem -LiteralPath $Data -Directory -Filter "prometheus-corrupt-*" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -le $cutoff } |
    Sort-Object LastWriteTime
)

$items = @()
$totalBytes = [int64]0
foreach ($item in $quarantines) {
  $fullPath = Assert-PathUnderRoot $item.FullName $Data
  $sizeBytes = Get-DirectorySizeBytes $fullPath
  $totalBytes += $sizeBytes

  if (-not $isDryRun) {
    Remove-Item -LiteralPath $fullPath -Recurse -Force
  }

  $items += [pscustomobject]@{
    Name = $item.Name
    Path = $fullPath
    LastWriteTime = $item.LastWriteTime.ToString("o")
    SizeMB = [math]::Round($sizeBytes / 1MB, 2)
    Action = if ($isDryRun) { "dry-run" } else { "deleted" }
  }
}

$result = [pscustomobject]@{
  Root = $Root
  Data = $Data
  MinAgeHours = $minimumAge
  DryRun = $isDryRun
  ConfirmCleanup = [bool]$ConfirmCleanup
  CandidateCount = $items.Count
  TotalSizeMB = [math]::Round($totalBytes / 1MB, 2)
  Items = $items
}

if ($Json) {
  $result | ConvertTo-Json -Depth 5
  exit 0
}

Write-Host "Prometheus quarantine cleanup"
Write-Host "Root: $Root"
Write-Host "Mode: $(if ($isDryRun) { "dry-run" } else { "delete" })"
Write-Host "Candidates: $($items.Count)"
Write-Host "Total size MB: $($result.TotalSizeMB)"
$items | Format-Table -AutoSize
