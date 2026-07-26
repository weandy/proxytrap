#!/usr/bin/env bash
# Backup SQLite (safe .backup) + raw JSONL into a timestamped tarball.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ROOT}/.env"
  set +a
fi

DATA_DIR="${DATA_DIR:-${ROOT}/data}"
OUT_DIR="${BACKUP_DIR:-${DATA_DIR}/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

mkdir -p "${OUT_DIR}" "${WORK}/raw" "${WORK}/exports"

DB="${DATA_DIR}/honeypot.db"
if [[ -f "${DB}" ]]; then
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${DB}" ".backup '${WORK}/honeypot.db'"
  else
    # Fallback: copy (stop writes if possible). Prefer sqlite3 on prod.
    cp -a "${DB}" "${WORK}/honeypot.db"
    [[ -f "${DB}-wal" ]] && cp -a "${DB}-wal" "${WORK}/" || true
    [[ -f "${DB}-shm" ]] && cp -a "${DB}-shm" "${WORK}/" || true
  fi
fi

if [[ -d "${DATA_DIR}/raw" ]]; then
  cp -a "${DATA_DIR}/raw/." "${WORK}/raw/" 2>/dev/null || true
fi
if [[ -d "${DATA_DIR}/exports" ]]; then
  cp -a "${DATA_DIR}/exports/." "${WORK}/exports/" 2>/dev/null || true
fi

ARCHIVE="${OUT_DIR}/honeypot-backup-${STAMP}.tar.gz"
tar -C "${WORK}" -czf "${ARCHIVE}" .
echo "wrote ${ARCHIVE}"
