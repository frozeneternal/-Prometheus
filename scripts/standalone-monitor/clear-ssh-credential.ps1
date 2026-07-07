param(
  [string]$Root = "E:\ops-monitor"
)

$ErrorActionPreference = "Stop"

$CredentialFile = Join-Path $Root "config\ssh-credential.local.xml"

if (Test-Path $CredentialFile) {
  Remove-Item -LiteralPath $CredentialFile -Force
  Write-Host "SSH credential removed: $CredentialFile"
} else {
  Write-Host "SSH credential file does not exist: $CredentialFile"
}
