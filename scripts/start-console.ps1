param(
  [string]$HostName = "127.0.0.1",
  [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Set-Location $Root
$env:PYTHONIOENCODING = "utf-8"
python app.py --host $HostName --port $Port
