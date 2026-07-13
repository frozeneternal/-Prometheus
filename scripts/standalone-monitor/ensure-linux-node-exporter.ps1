param(
  [string]$Root = "E:\ops-monitor",
  [string]$HostFilter = "",
  [string]$ListenAddress = "",
  [int]$VerifyTimeoutSeconds = 15,
  [switch]$Apply,
  [switch]$Json
)

$ErrorActionPreference = "Stop"

$Config = Join-Path $Root "config"
$TargetsFile = Join-Path $Config "targets.local.json"
$TunnelsFile = Join-Path $Config "tunnels.local.json"
$CredentialFile = Join-Path $Config "ssh-credential.local.xml"
$Worker = Join-Path $Root "scripts\ensure_linux_node_exporter.py"

if (-not (Test-Path $TargetsFile)) {
  throw "Missing target inventory: $TargetsFile"
}
if (-not (Test-Path $Worker)) {
  throw "Missing worker script: $Worker"
}

if ((-not $env:OPS_SSH_USER -or -not $env:OPS_SSH_PASSWORD) -and (Test-Path $CredentialFile)) {
  $credential = Import-Clixml -LiteralPath $CredentialFile
  $env:OPS_SSH_USER = $credential.UserName
  $env:OPS_SSH_PASSWORD = $credential.GetNetworkCredential().Password
}
if (-not $env:OPS_SSH_USER -or -not $env:OPS_SSH_PASSWORD) {
  throw "OPS_SSH_USER and OPS_SSH_PASSWORD must be set, or $CredentialFile must exist."
}

$arguments = @(
  $Worker,
  "--targets",
  $TargetsFile
)

if (Test-Path $TunnelsFile) {
  $arguments += @("--tunnels", $TunnelsFile)
}
if ($HostFilter) {
  $arguments += @("--host-filter", $HostFilter)
}
if ($ListenAddress) {
  $arguments += @("--listen-address", $ListenAddress)
}
$arguments += @("--verify-timeout", [string]$VerifyTimeoutSeconds)
if ($Apply) {
  $arguments += "--apply"
}
if ($Json) {
  $arguments += "--json"
}

& python @arguments
exit $LASTEXITCODE
