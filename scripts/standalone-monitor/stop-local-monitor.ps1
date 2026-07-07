param(
  [string]$Root = "E:\ops-monitor"
)

$ErrorActionPreference = "Stop"

$Run = Join-Path $Root "run"

foreach ($name in @("grafana", "prometheus", "blackbox_exporter", "windows_exporter")) {
  $pidFile = Join-Path $Run "$name.pid"
  if (-not (Test-Path $pidFile)) {
    Write-Host "$name: no pid file"
    continue
  }
  $pidValue = Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue
  if (-not $pidValue) {
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    continue
  }
  $proc = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
  if (-not $proc) {
    Write-Host "$name: not running"
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    continue
  }
  $path = $proc.Path
  if (-not $path -or -not $path.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Host "$name: PID $pidValue is not owned by $Root, skipped"
    continue
  }
  Stop-Process -Id $proc.Id -Force
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  Write-Host "$name: stopped PID $pidValue"
}
