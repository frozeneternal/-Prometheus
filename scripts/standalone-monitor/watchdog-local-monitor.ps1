param(
  [string]$Root = "E:\ops-monitor",
  [int]$ScriptTimeoutSeconds = 45
)

$ErrorActionPreference = "Continue"

$Config = Join-Path $Root "config"
$Logs = Join-Path $Root "logs"
$WatchdogLog = Join-Path $Logs "watchdog-local-monitor.log"
$RecoverPrometheus = Join-Path $Root "scripts\recover-prometheus-tsdb.ps1"
$StartLocal = Join-Path $Root "scripts\start-local-monitor.ps1"
$StartTunnels = Join-Path $Root "scripts\start-ssh-tunnels.ps1"
$TunnelsConfig = Join-Path $Config "tunnels.local.json"

New-Item -ItemType Directory -Force -Path $Logs | Out-Null

function Write-WatchdogLog($Message) {
  $line = "$(Get-Date -Format o) $Message"
  Add-Content -LiteralPath $WatchdogLog -Value $line -Encoding UTF8
  Write-Host $line
}

function Get-HttpStatus($Url) {
  try {
    return (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3).StatusCode
  } catch {
    return "ERR"
  }
}

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

function Test-TunnelMetrics($HostName, $Port) {
  $url = "http://$HostName`:$Port/metrics"
  $status = Get-HttpStatus $url
  return @{
    Ok = ($status -eq 200)
    Status = $status
    Url = $url
  }
}

function Test-PrometheusTsdbCorruption {
  $path = Join-Path $Logs "prometheus.err.log"
  if (-not (Test-Path -LiteralPath $path)) {
    return $false
  }
  $patterns = @(
    "fatal error: fault",
    "checkCRC32",
    "Encountered WAL read error",
    "corruption in segment",
    "unexpected fault address"
  )
  foreach ($pattern in $patterns) {
    if (Select-String -LiteralPath $path -Pattern $pattern -SimpleMatch -Quiet -ErrorAction SilentlyContinue) {
      return $true
    }
  }
  return $false
}

function ConvertTo-MonitorScriptArguments([string[]]$Arguments) {
  if (-not $Arguments) {
    return ""
  }
  $quoted = @()
  foreach ($argument in $Arguments) {
    $value = [string]$argument
    if ($value -match '^-?[A-Za-z0-9_.:-]+$') {
      $quoted += " $value"
    } else {
      $quoted += " '$($value.Replace("'", "''"))'"
    }
  }
  return ($quoted -join "")
}

function Start-HiddenPowerShellProcess($EncodedCommand, $WorkingDirectory) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = "powershell.exe"
  $psi.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand"
  $psi.WorkingDirectory = $WorkingDirectory
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true

  $proc = [System.Diagnostics.Process]::new()
  $proc.StartInfo = $psi
  [void]$proc.Start()
  return @{
    Process = $proc
    StdoutTask = $proc.StandardOutput.ReadToEndAsync()
    StderrTask = $proc.StandardError.ReadToEndAsync()
  }
}

function Save-ProcessOutput($Path, $OutputTask) {
  $text = ""
  if ($OutputTask) {
    $text = [string]$OutputTask.Result
  }
  Set-Content -LiteralPath $Path -Value $text -NoNewline -Encoding UTF8
}

function Invoke-MonitorScript($ScriptPath, $Name, [string[]]$ExtraArguments = @()) {
  if (-not (Test-Path $ScriptPath)) {
    Write-WatchdogLog "$Name script missing: $ScriptPath"
    return
  }

  $safeName = $Name -replace '[^A-Za-z0-9_.-]', '_'
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $stdout = Join-Path $Logs "watchdog-$safeName-$stamp.out.log"
  $stderr = Join-Path $Logs "watchdog-$safeName-$stamp.err.log"
  $ExitCodeFile = Join-Path $Logs "watchdog-$safeName-$stamp.exitcode"
  $timeoutMs = [Math]::Max(1, $ScriptTimeoutSeconds) * 1000

  try {
    $safeScript = ([string]$ScriptPath).Replace("'", "''")
    $safeRoot = ([string]$Root).Replace("'", "''")
    $safeExitCodeFile = ([string]$ExitCodeFile).Replace("'", "''")
    $argumentText = ConvertTo-MonitorScriptArguments $ExtraArguments
    $command = @"
`$ExitCodeFile = '$safeExitCodeFile'
try {
  & '$safeScript' -Root '$safeRoot'$argumentText
  if (`$global:LASTEXITCODE -ne `$null) {
    `$exitCode = `$global:LASTEXITCODE
  } elseif (`$?) {
    `$exitCode = 0
  } else {
    `$exitCode = 1
  }
} catch {
  Write-Error `$_.Exception.Message
  `$exitCode = 1
}
Set-Content -LiteralPath `$ExitCodeFile -Value `$exitCode -Encoding ASCII
exit `$exitCode
"@

    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $started = Start-HiddenPowerShellProcess -EncodedCommand $encodedCommand -WorkingDirectory $Root
    $proc = $started.Process
    $timedOut = $false
    if (-not $proc.WaitForExit($timeoutMs)) {
      $timedOut = $true
      Write-WatchdogLog "$Name did not exit within $ScriptTimeoutSeconds seconds; terminating wrapper process: PID $($proc.Id)"
      $proc.Kill()
      $proc.WaitForExit()
    }

    Save-ProcessOutput $stdout $started.StdoutTask
    Save-ProcessOutput $stderr $started.StderrTask
    if ($timedOut) {
      return
    }

    $exitCode = "unknown"
    if (Test-Path $ExitCodeFile) {
      $exitCode = (Get-Content -Raw -LiteralPath $ExitCodeFile -ErrorAction SilentlyContinue).Trim()
    }
    Write-WatchdogLog "$Name exited with code $exitCode"

    if (Test-Path $stdout) {
      $stdoutLines = Get-Content -LiteralPath $stdout -Tail 20 -ErrorAction SilentlyContinue
      foreach ($line in $stdoutLines) {
        if ($line) {
          Write-WatchdogLog "$Name stdout: $line"
        }
      }
    }
    if (Test-Path $stderr) {
      $stderrLines = Get-Content -LiteralPath $stderr -Tail 20 -ErrorAction SilentlyContinue
      foreach ($line in $stderrLines) {
        if ($line) {
          Write-WatchdogLog "$Name stderr: $line"
        }
      }
    }
  } catch {
    Write-WatchdogLog "$Name failed to run: $($_.Exception.Message)"
  }
}

$localChecks = @(
  @{Name="grafana"; Url="http://127.0.0.1:3000/api/health"},
  @{Name="prometheus"; Url="http://127.0.0.1:19090/-/ready"},
  @{Name="blackbox_exporter"; Url="http://127.0.0.1:19115/metrics"},
  @{Name="windows_exporter"; Url="http://127.0.0.1:9182/metrics"}
)

$localFailed = @()
$prometheusStatus = $null
foreach ($check in $localChecks) {
  $status = Get-HttpStatus $check.Url
  if ($check.Name -eq "prometheus") {
    $prometheusStatus = $status
  }
  if ($status -ne 200) {
    $localFailed += "$($check.Name)=$status"
  }
}

if (($prometheusStatus -ne 200) -and (Test-PrometheusTsdbCorruption)) {
  Write-WatchdogLog "prometheus unhealthy and TSDB corruption signature found; running recover-prometheus-tsdb.ps1"
  Invoke-MonitorScript $RecoverPrometheus "recover-prometheus-tsdb" @("-StartAfterRecovery")
} elseif ($localFailed.Count -gt 0) {
  Write-WatchdogLog "local stack unhealthy: $($localFailed -join ', '); running start-local-monitor.ps1"
  Invoke-MonitorScript $StartLocal "start-local-monitor"
} else {
  Write-WatchdogLog "local stack healthy"
}

if (Test-Path $TunnelsConfig) {
  try {
    $inventory = Get-Content -Raw -Encoding UTF8 -LiteralPath $TunnelsConfig | ConvertFrom-Json
    $closed = @()
    $badMetrics = @()
    foreach ($tunnel in $inventory.tunnels) {
      if ($tunnel.enabled -eq $false) {
        continue
      }
      $localHost = "127.0.0.1"
      if ($tunnel.localHost) {
        $localHost = [string]$tunnel.localHost
      }
      $localPort = [int]$tunnel.localPort
      if (-not (Test-PortFast $localHost $localPort)) {
        $closed += "$($tunnel.name)=$localHost`:$localPort"
        continue
      }
      $metrics = Test-TunnelMetrics $localHost $localPort
      if (-not $metrics.Ok) {
        $badMetrics += "$($tunnel.name)=$($metrics.Url) status=$($metrics.Status)"
      }
    }
    if ($closed.Count -gt 0) {
      Write-WatchdogLog "ssh tunnel listeners unhealthy: $($closed -join ', '); running start-ssh-tunnels.ps1"
      Invoke-MonitorScript $StartTunnels "start-ssh-tunnels" @("-Restart")
    } elseif ($badMetrics.Count -gt 0) {
      Write-WatchdogLog "ssh tunnel metrics unhealthy: $($badMetrics -join ', '); running start-ssh-tunnels.ps1"
      Invoke-MonitorScript $StartTunnels "start-ssh-tunnels" @("-Restart")
    } else {
      Write-WatchdogLog "ssh tunnel listeners healthy; metrics healthy"
    }
  } catch {
    Write-WatchdogLog "failed to inspect ssh tunnel config: $($_.Exception.Message)"
  }
}
