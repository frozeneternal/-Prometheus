$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$StartAll = Join-Path $PSScriptRoot "start-all.cmd"
$HiddenLauncher = Join-Path $PSScriptRoot "run-hidden.vbs"
$TaskName = "LocalMonitorStartup"

if (-not (Test-Path $StartAll)) {
  throw "Missing startup script: $StartAll"
}
if (-not (Test-Path $HiddenLauncher)) {
  throw "Missing hidden launcher script: $HiddenLauncher"
}

function ConvertTo-HiddenLauncherArguments([string[]]$Arguments) {
  $quoted = @()
  foreach ($argument in $Arguments) {
    $value = [string]$argument
    $quoted += "`"$($value.Replace('"', '\"'))`""
  }
  return ($quoted -join " ")
}

$startupArguments = ConvertTo-HiddenLauncherArguments @(
  $HiddenLauncher,
  "powershell.exe",
  "-NoProfile",
  "-NonInteractive",
  "-WindowStyle",
  "Hidden",
  "-ExecutionPolicy",
  "Bypass",
  "-Command",
  "& '$($StartAll.Replace("'", "''"))'; exit `$LASTEXITCODE"
)

$Action = New-ScheduledTaskAction `
  -Execute "wscript.exe" `
  -Argument "//B $startupArguments" `
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
