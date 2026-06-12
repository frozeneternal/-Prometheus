$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$StartAll = Join-Path $PSScriptRoot "start-all.cmd"
$TaskName = "LocalMonitorStartup"

if (-not (Test-Path $StartAll)) {
  throw "Missing startup script: $StartAll"
}

$Action = New-ScheduledTaskAction `
  -Execute "cmd.exe" `
  -Argument "/c `"$StartAll`"" `
  -WorkingDirectory $Root

$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 2)

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
