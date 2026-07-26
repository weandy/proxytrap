# Backup SQLite + raw JSONL on Windows.
# Usage: .\scripts\backup.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$DataDir = if ($env:DATA_DIR) { $env:DATA_DIR } else { Join-Path $Root "data" }
$OutDir = if ($env:BACKUP_DIR) { $env:BACKUP_DIR } else { Join-Path $DataDir "backups" }
$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$Work = Join-Path $env:TEMP ("honeypot-backup-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $Work, (Join-Path $Work "raw"), (Join-Path $Work "exports"), $OutDir | Out-Null

try {
  $Db = Join-Path $DataDir "honeypot.db"
  if (Test-Path $Db) {
    $sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
    if ($sqlite) {
      $dest = (Join-Path $Work "honeypot.db") -replace "\\", "/"
      $src = $Db -replace "\\", "/"
      & sqlite3 $src ".backup '$dest'"
    } else {
      Copy-Item $Db (Join-Path $Work "honeypot.db")
      foreach ($suf in @("-wal", "-shm")) {
        $p = $Db + $suf
        if (Test-Path $p) { Copy-Item $p $Work }
      }
    }
  }
  $raw = Join-Path $DataDir "raw"
  if (Test-Path $raw) { Copy-Item (Join-Path $raw "*") (Join-Path $Work "raw") -Recurse -ErrorAction SilentlyContinue }
  $exp = Join-Path $DataDir "exports"
  if (Test-Path $exp) { Copy-Item (Join-Path $exp "*") (Join-Path $Work "exports") -Recurse -ErrorAction SilentlyContinue }

  $Archive = Join-Path $OutDir "honeypot-backup-$Stamp.zip"
  Compress-Archive -Path (Join-Path $Work "*") -DestinationPath $Archive -Force
  Write-Host "wrote $Archive"
}
finally {
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
