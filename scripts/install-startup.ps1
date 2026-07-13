$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$StartAll = Join-Path $PSScriptRoot "start-all.cmd"
$TaskName = "LocalMonitorStartup"

if (-not (Test-Path $StartAll)) {
  throw "Missing startup script: $StartAll"
}

$SafeRoot = $Root.Replace("'", "''")
$SafeStartAll = $StartAll.Replace("'", "''")
$StartupCommand = "Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', '$SafeStartAll') -WorkingDirectory '$SafeRoot' -WindowStyle Hidden -Wait"
$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$StartupCommand`"" `
  -WorkingDirectory $Root

$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 2)
$Settings.Hidden = $true

$Principal = New-ScheduledTaskPrincipal `
  -UserId $env:USERNAME `
  -LogonType Interactive `
  -RunLevel Highest

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $Action `
  -Trigger $Trigger `
  -Settings $Settings `
  -Principal $Principal `
  -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed and started scheduled task: $TaskName"
Write-Host "Console: http://127.0.0.1:8787/"
