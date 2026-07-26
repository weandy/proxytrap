# One-click local run helper for Windows (dev / single machine).
# Usage (PowerShell, as admin optional):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\deploy\install.ps1
# Does NOT install a Windows Service by default — creates venv, .env, and starts run.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

Write-Host "[+] Repo: $Root"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw "需要 Python 3.11+ 在 PATH 中"
}

if (-not (Test-Path ".venv")) {
  Write-Host "[+] Creating venv..."
  python -m venv .venv
}

$pip = Join-Path $Root ".venv\Scripts\pip.exe"
$py = Join-Path $Root ".venv\Scripts\python.exe"
& $pip install -U pip wheel -q
& $pip install -e ".[dev]" -q

$envFile = Join-Path $Root ".env"
if (-not (Test-Path $envFile)) {
  $pass = -join ((48..57 + 97..102) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
  $secret = -join ((48..57 + 97..102) | Get-Random -Count 48 | ForEach-Object { [char]$_ })
  @"
DATA_DIR=$Root\data
CONFIG_PATH=$Root\config\config.example.yaml
HONEYPOT_BIND=0.0.0.0
AUTH_MODE=always_fail
WEB_ENABLED=true
WEB_BIND=127.0.0.1:8787
WEB_AUTH_USER=admin
WEB_PASSWORD=$pass
WEB_SESSION_SECRET=$secret
LOG_LEVEL=info
"@ | Set-Content -Path $envFile -Encoding UTF8
  Write-Host "[+] Wrote .env  WEB_PASSWORD=$pass"
} else {
  Write-Host "[!] .env exists, not overwriting"
}

Write-Host "[+] Done. Start with:"
Write-Host "    .\.venv\Scripts\python.exe -m honeypot run"
Write-Host "    Open http://127.0.0.1:8787"
