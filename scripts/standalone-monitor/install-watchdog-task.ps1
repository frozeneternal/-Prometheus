param(
  [string]$Root = "E:\ops-monitor",
  [string]$TaskName = "OpsMonitorWatchdog",
  [int]$IntervalMinutes = 5
)

$ErrorActionPreference = "Stop"

$Watchdog = Join-Path $Root "scripts\watchdog-local-monitor.ps1"
$Logs = Join-Path $Root "logs"

if (-not (Test-Path $Watchdog)) {
  throw "Missing watchdog script: $Watchdog"
}

New-Item -ItemType Directory -Force -Path $Logs | Out-Null

$interval = [Math]::Max(1, $IntervalMinutes)
$startAt = (Get-Date).AddMinutes(1)
$trigger = New-ScheduledTaskTrigger `
  -Once `
  -At $startAt `
  -RepetitionInterval (New-TimeSpan -Minutes $interval) `
  -RepetitionDuration (New-TimeSpan -Days 3650)

$action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Watchdog`" -Root `"$Root`"" `
  -WorkingDirectory $Root

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 3)

$principal = New-ScheduledTaskPrincipal `
  -UserId $env:USERNAME `
  -LogonType Interactive `
  -RunLevel Highest

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Principal $principal `
  -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed and started scheduled task: $TaskName"
Write-Host "Watchdog: $Watchdog"
Write-Host "Interval: ${interval} minutes"
