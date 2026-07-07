param(
  [string]$Root = "E:\ops-monitor",
  [string]$UserName = "",
  [SecureString]$Password,
  [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = "Stop"

$Config = Join-Path $Root "config"
$CredentialFile = Join-Path $Config "ssh-credential.local.xml"

New-Item -ItemType Directory -Force -Path $Config | Out-Null

if (-not $Credential) {
  if ($UserName -and $Password) {
    $Credential = [System.Management.Automation.PSCredential]::new($UserName, $Password)
  } else {
    $Credential = Get-Credential -Message "Enter SSH credential for metrics tunnels"
  }
}

$Credential | Export-Clixml -LiteralPath $CredentialFile
Write-Host "SSH credential saved to $CredentialFile for the current Windows user."
