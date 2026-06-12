$ErrorActionPreference = "Stop"

$DockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
$TimeoutSeconds = 120
$StartedAt = Get-Date

$Service = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
if ($Service -and $Service.Status -ne "Running") {
  Start-Service -Name "com.docker.service"
}

if (Test-Path $DockerDesktop) {
  $DockerProcess = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue
  if (-not $DockerProcess) {
    Start-Process -FilePath $DockerDesktop -WindowStyle Hidden
  }
}

while (((Get-Date) - $StartedAt).TotalSeconds -lt $TimeoutSeconds) {
  docker version *> $null
  if ($LASTEXITCODE -eq 0) {
    exit 0
  }

  Start-Sleep -Seconds 5
}

throw "Docker daemon did not become ready within $TimeoutSeconds seconds."
