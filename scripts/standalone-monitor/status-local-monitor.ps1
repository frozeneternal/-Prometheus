param(
  [string]$Root = "E:\ops-monitor",
  [switch]$Json,
  [switch]$DeepDiskScan,
  [switch]$LocalOnly
)

$ErrorActionPreference = "Continue"

$TargetsFile = Join-Path $Root "config\targets.local.json"

function ConvertTo-ProcessArgumentString([string[]]$ArgumentList) {
  ($ArgumentList | ForEach-Object {
    if ($_ -match '\s') {
      '"' + ($_ -replace '"', '\"') + '"'
    } else {
      $_
    }
  }) -join " "
}

function Invoke-CapturedProcess($FilePath, [string[]]$ArgumentList, $TimeoutSeconds = 8) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $FilePath
  $psi.Arguments = ConvertTo-ProcessArgumentString $ArgumentList
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true

  $proc = [System.Diagnostics.Process]::new()
  $proc.StartInfo = $psi

  try {
    [void]$proc.Start()
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $completed) {
      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
      return [pscustomobject]@{Status="timeout"; ExitCode=$null; Output=""; Error="version command timed out after ${TimeoutSeconds}s"}
    }

    $out = $stdoutTask.Result.Trim()
    $err = $stderrTask.Result.Trim()
    $status = if ($proc.ExitCode -eq 0) { "ok" } else { "error" }
    return [pscustomobject]@{Status=$status; ExitCode=$proc.ExitCode; Output=$out; Error=$err}
  } catch {
    return [pscustomobject]@{Status="error"; ExitCode=$null; Output=""; Error=$_.Exception.Message}
  } finally {
    $proc.Dispose()
  }
}

function Invoke-VersionCommand($FilePath, [string[]]$ArgumentList, $TimeoutSeconds = 8) {
  Invoke-CapturedProcess -FilePath $FilePath -ArgumentList $ArgumentList -TimeoutSeconds $TimeoutSeconds
}

function Get-ExecutableVersionStatus($Name, $RelativePath, [string[]]$ArgumentList) {
  $path = Join-Path $Root (Join-Path "apps" $RelativePath)
  if (-not (Test-Path -LiteralPath $path)) {
    return [pscustomobject]@{Name=$Name; Status="missing"; ExitCode=$null; Version=""; Error="missing executable"; Path=$path}
  }

  $result = Invoke-VersionCommand -FilePath $path -ArgumentList $ArgumentList
  $versionOutput = if ($result.Output.Trim()) { $result.Output } elseif ($result.ExitCode -eq 0) { $result.Error } else { "" }
  $lines = @($versionOutput -split "`r?`n" | Where-Object { $_.Trim() })
  $version = if ($lines.Count -gt 0) { $lines[0].Trim() } else { "" }
  $errorMessage = if ($result.Status -eq "ok") { "" } else { $result.Error }
  [pscustomobject]@{
    Name = $Name
    Status = $result.Status
    ExitCode = $result.ExitCode
    Version = $version
    Error = $errorMessage
    Path = $path
  }
}

function Get-AppDirectoryStatus($Name, $RelativePath) {
  $path = Join-Path $Root (Join-Path "apps" $RelativePath)
  try {
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $target = if ($item.Target) { ($item.Target -join ", ") } else { "" }
    [pscustomobject]@{Name=$Name; Status="ok"; LinkType=$item.LinkType; Target=$target; Path=$path}
  } catch {
    [pscustomobject]@{Name=$Name; Status="missing"; LinkType=""; Target=""; Path=$path}
  }
}

function Invoke-DeepDiskScan($DriveLetter, $TimeoutSeconds = 300) {
  try {
    $args = @("${DriveLetter}:", "/scan")
    $result = Invoke-CapturedProcess -FilePath "$env:SystemRoot\System32\chkdsk.exe" -ArgumentList $args -TimeoutSeconds $TimeoutSeconds
    if ($result.Status -eq "timeout") {
      return [pscustomobject]@{Status="timeout"; ExitCode=$null; Summary="chkdsk /scan timed out after ${TimeoutSeconds}s"}
    }

    $out = $result.Output
    $err = $result.Error
    $summary = (($out -split "`r?`n") + ($err -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 8) -join " | "
    $status = if ($result.ExitCode -eq 0) { "ok" } else { "warning" }
    [pscustomobject]@{Status=$status; ExitCode=$result.ExitCode; Summary=$summary}
  } catch {
    [pscustomobject]@{Status="error"; ExitCode=$null; Summary=$_.Exception.Message}
  }
}

function Get-RootVolumeStatus {
  try {
    $resolvedRoot = (Get-Item -LiteralPath $Root -ErrorAction Stop).FullName
    $drive = (Split-Path -Qualifier $resolvedRoot).TrimEnd(":")
    $volume = Get-Volume -DriveLetter $drive -ErrorAction Stop
    $freePercent = if ($volume.Size) { [math]::Round(($volume.SizeRemaining / $volume.Size) * 100, 2) } else { $null }
    $status = "ok"
    if ($volume.HealthStatus -and $volume.HealthStatus.ToString() -ne "Healthy") {
      $status = "warning"
    }
    if ($freePercent -ne $null -and $freePercent -lt 10) {
      $status = "warning"
    }
    if ($freePercent -ne $null -and $freePercent -lt 5) {
      $status = "critical"
    }

    $scan = if ($DeepDiskScan) {
      Invoke-DeepDiskScan -DriveLetter $drive
    } else {
      [pscustomobject]@{Status="skipped"; ExitCode=$null; Summary="run with -DeepDiskScan to execute chkdsk /scan"}
    }

    [pscustomobject]@{
      Status = $status
      Drive = "${drive}:"
      HealthStatus = $volume.HealthStatus
      OperationalStatus = ($volume.OperationalStatus -join ", ")
      FreePercent = $freePercent
      SizeGB = if ($volume.Size) { [math]::Round($volume.Size / 1GB, 2) } else { $null }
      FreeGB = if ($volume.SizeRemaining) { [math]::Round($volume.SizeRemaining / 1GB, 2) } else { $null }
      DeepScanStatus = $scan.Status
      DeepScanExitCode = $scan.ExitCode
      DeepScanSummary = $scan.Summary
      Path = $resolvedRoot
    }
  } catch {
    [pscustomobject]@{
      Status = "error"
      Drive = ""
      HealthStatus = ""
      OperationalStatus = ""
      FreePercent = $null
      SizeGB = $null
      FreeGB = $null
      DeepScanStatus = "skipped"
      DeepScanExitCode = $null
      DeepScanSummary = ""
      Path = $Root
      Error = $_.Exception.Message
    }
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

function Get-HttpStatus($Url) {
  try {
    return (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3).StatusCode
  } catch {
    return "ERR"
  }
}

$local = @(
  [pscustomobject]@{Name="Grafana"; Url="http://127.0.0.1:3000/api/health"; Status=Get-HttpStatus "http://127.0.0.1:3000/api/health"},
  [pscustomobject]@{Name="Prometheus"; Url="http://127.0.0.1:19090/-/ready"; Status=Get-HttpStatus "http://127.0.0.1:19090/-/ready"},
  [pscustomobject]@{Name="Blackbox exporter"; Url="http://127.0.0.1:19115/metrics"; Status=Get-HttpStatus "http://127.0.0.1:19115/metrics"},
  [pscustomobject]@{Name="Windows exporter"; Url="http://127.0.0.1:9182/metrics"; Status=Get-HttpStatus "http://127.0.0.1:9182/metrics"}
)

$binaryHealth = @(
  Get-ExecutableVersionStatus -Name "Prometheus" -RelativePath "prometheus\prometheus.exe" -ArgumentList @("--version")
  Get-ExecutableVersionStatus -Name "Grafana" -RelativePath "grafana\bin\grafana.exe" -ArgumentList @("-v")
  Get-ExecutableVersionStatus -Name "Blackbox exporter" -RelativePath "blackbox_exporter\blackbox_exporter.exe" -ArgumentList @("--version")
  Get-ExecutableVersionStatus -Name "Windows exporter" -RelativePath "windows_exporter\windows_exporter.exe" -ArgumentList @("--version")
)

$appDirectoryHealth = @(
  Get-AppDirectoryStatus -Name "Prometheus app dir" -RelativePath "prometheus"
  Get-AppDirectoryStatus -Name "Grafana app dir" -RelativePath "grafana"
  Get-AppDirectoryStatus -Name "Blackbox exporter app dir" -RelativePath "blackbox_exporter"
  Get-AppDirectoryStatus -Name "Windows exporter app dir" -RelativePath "windows_exporter"
)

$rootVolumeHealth = Get-RootVolumeStatus

$remote = @()
if (-not $LocalOnly -and (Test-Path $TargetsFile)) {
  $inventory = Get-Content -Raw -Encoding UTF8 -LiteralPath $TargetsFile | ConvertFrom-Json
  $remote = foreach ($server in $inventory.servers) {
    $metricsPort = if ($server.os -eq "windows") { 9182 } else { 9100 }
    [pscustomobject]@{
      Name = $server.name
      IP = $server.ip
      OS = $server.os
      SSH22 = Test-PortFast $server.ip 22
      MetricsPort = $metricsPort
      MetricsOpen = Test-PortFast $server.ip $metricsPort
    }
  }
}

$active = @()
if (-not $LocalOnly) {
  try {
    $targets = Invoke-RestMethod -Uri "http://127.0.0.1:19090/api/v1/targets" -TimeoutSec 5
    $active = $targets.data.activeTargets | ForEach-Object {
      [pscustomobject]@{
        Job = $_.labels.job
        Instance = $_.labels.instance
        Name = $_.labels.name
        Health = $_.health
        LastError = $_.lastError
      }
    }
  } catch {
    $prometheusTargetsError = $_.Exception.Message
  }
}

if ($Json) {
  [pscustomobject]@{
    localStack = $local
    runtimeBinaryHealth = $binaryHealth
    appDirectoryHealth = $appDirectoryHealth
    rootVolumeHealth = $rootVolumeHealth
    remoteTargets = @($remote)
    prometheusTargets = @($active)
    prometheusTargetsError = $prometheusTargetsError
  } | ConvertTo-Json -Depth 6
  exit 0
}

Write-Host "Local stack"
$local | Format-Table -AutoSize

Write-Host ""
Write-Host "Runtime binary health"
$binaryHealth | Format-Table -AutoSize

Write-Host ""
Write-Host "App directory placement"
$appDirectoryHealth | Format-Table -AutoSize

Write-Host ""
Write-Host "Root volume health"
$rootVolumeHealth | Format-List

if ($remote) {
  Write-Host ""
  Write-Host "Remote targets"
  $remote | Format-Table -AutoSize
}

Write-Host ""
if ($prometheusTargetsError) {
  Write-Host "Prometheus targets unavailable: $prometheusTargetsError"
} else {
  Write-Host "Prometheus targets"
  $active | Format-Table -AutoSize
}
