$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$LocalConfig = Join-Path $Root "config\servers.local.json"
$PublicConfig = Join-Path $Root "config\servers.json"
$Config = if (Test-Path $LocalConfig) { $LocalConfig } else { $PublicConfig }

Write-Host "Monitor root: $Root"
Write-Host "Active config: $Config"

try {
  $Json = Get-Content -Encoding UTF8 -Raw -Path $Config | ConvertFrom-Json
  $ServerCount = @($Json.servers).Count
  $WebsiteCount = @($Json.websites).Count
  Write-Host "Configured servers: $ServerCount"
  Write-Host "Configured websites: $WebsiteCount"
} catch {
  Write-Host "Config parse failed: $($_.Exception.Message)"
}

try {
  $Ready = Invoke-RestMethod -Uri "http://127.0.0.1:8787/api/prometheus/ready" -TimeoutSec 5
  Write-Host "Console -> Prometheus: $($Ready.ok) $($Ready.message)"
} catch {
  Write-Host "Console -> Prometheus: unavailable ($($_.Exception.Message))"
}

try {
  $Response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8787/" -TimeoutSec 5
  Write-Host "Console page: HTTP $($Response.StatusCode)"
} catch {
  Write-Host "Console page: unavailable ($($_.Exception.Message))"
}

$DockerService = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
if ($DockerService) {
  Write-Host "Docker service: $($DockerService.Status)"
} else {
  Write-Host "Docker service: not installed"
}

try {
  docker version *> $null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker daemon: ready"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  } else {
    Write-Host "Docker daemon: not ready"
  }
} catch {
  Write-Host "Docker daemon: not ready ($($_.Exception.Message))"
}
