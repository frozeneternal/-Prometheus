$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Set-Location $Root
& (Join-Path $PSScriptRoot "wait-docker.ps1")
if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
  docker-compose -p localmonitor up -d
} else {
  docker compose -p localmonitor up -d
}
