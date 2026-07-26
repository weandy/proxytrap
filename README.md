# Proxy Auth Honeypot

SOCKS5 / HTTP **proxy authentication honeypot** for collecting real-world brute-force credentials.

Persists events to **daily JSONL** + **SQLite** aggregates, optional **Web UI** (Session login), **dynamic ports**, credential **export**, Phase-3 ops, and **AI chat/analysis** (custom OpenAI-compatible endpoint; settings stored under `DATA_DIR`, not `.env`).

**Never forwards traffic. Not an open proxy. L3 is intentionally unsupported.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

| Area | What you get |
|------|----------------|
| Protocols | SOCKS5 (RFC1929 user/pass), HTTP proxy (407 + Basic, CONNECT marked) |
| Deception | L1 `always_fail` (default); L2 `accept_then_fail` (auth “ok”, CONNECT fails, no dial) |
| Storage | `data/raw/events-YYYY-MM-DD.jsonl` + `data/honeypot.db` |
| Web | Dashboard, credentials, sources, events, ports, **system/disk** |
| Ops | Retention, `reindex`, `disk`, auto daily export, stale-auth warning, `/healthz` |
| AI | Web **AI** page: custom base URL / API key / model (fetch list), chat + preset analysis with live honeypot snapshot; config → `data/ai_settings.json` |
| Deploy | `deploy/proxy-honeypot.service`, `scripts/backup.sh` / `.ps1` |

## Quick start (dev)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate

pip install -e ".[dev]"
cp .env.example .env   # set WEB_PASSWORD and WEB_SESSION_SECRET

export DATA_DIR=./data
export CONFIG_PATH=./config/config.example.yaml
export WEB_ENABLED=true
export WEB_BIND=127.0.0.1:8787
export WEB_AUTH_USER=admin
export WEB_PASSWORD=please-change-me
export WEB_SESSION_SECRET=please-change-session-secret

python -m honeypot run
```

Open `http://127.0.0.1:8787` → login → Dashboard / Credentials / Ports / System.

```bash
python -m honeypot export --top 1000 --format userpass -o data/exports/wordlist.txt
python -m honeypot export --port 1080 --protocol socks5
python -m honeypot reindex
python -m honeypot disk
pytest -q
```

## Production deploy

See **[deploy/README.md](deploy/README.md)** and **[docs/deploy-cloud.md](docs/deploy-cloud.md)**.

Short path:

1. Install into `/opt/proxy-honeypot` with venv + `pip install -e .`
2. Configure `.env` (`DATA_DIR`, strong `WEB_*` secrets; prefer `WEB_BIND=127.0.0.1:8787`)
3. Install `deploy/proxy-honeypot.service` → `systemctl enable --now proxy-honeypot`
4. Open honeypot ports on the security group; **restrict Web and SSH**
5. Cron or manual: `scripts/backup.sh`

## CLI

| Command | Purpose |
|---------|---------|
| `honeypot run` | Start listeners + optional Web + maintenance loop |
| `honeypot export` | Wordlist from SQLite (`--format`, `--port`, `--protocol`) |
| `honeypot reindex` | Rebuild SQLite from JSONL (source of truth) |
| `honeypot disk` | Print data-dir usage |

## Configuration

- **Env (minimal)**: [.env.example](.env.example) — `DATA_DIR` / port YAML path / Web admin password  
- **AI**: configure in Web → **AI** (endpoint, key, model). Saved to `DATA_DIR/ai_settings.json` (gitignored via `data/`)  
- **Ports / deception YAML**: [config/config.example.yaml](config/config.example.yaml)

| Env | Meaning |
|-----|---------|
| `AUTH_MODE` | `always_fail` \| `accept_then_fail` |
| `EVENTS_RETENTION_DAYS` | Purge SQLite `events` older than N days (`0`=off) |
| `JSONL_RETENTION_DAYS` | Delete old `events-*.jsonl` (`0`=off) |
| `AUTH_STALE_WARN_HOURS` | Log warning if no auth for N hours |
| `AUTO_EXPORT_HOURS` | Enable daily export to `data/exports/daily-YYYY-MM-DD.txt` when &gt;0 |

## L2 vs L3

| Mode | Behavior | Use |
|------|----------|-----|
| L1 `always_fail` | Auth always fails | Default; best for sustained dictionary dumps |
| L2 `accept_then_fail` | Auth success, then CONNECT/business fails | Optional experiment; still **no outbound** |
| L3 forward | Real proxy | **Not implemented / forbidden** |

## Documentation

| Doc | Content |
|-----|---------|
| [docs/requirements.md](docs/requirements.md) | Requirements freeze |
| [docs/architecture.md](docs/architecture.md) | Architecture |
| [docs/phases/](docs/phases/) | Phase 1–3 status |
| [docs/deploy-cloud.md](docs/deploy-cloud.md) | Cloud SG + abuse FAQ |
| [deploy/README.md](deploy/README.md) | systemd install |

## Related projects (inspiration only)

| Project | Idea borrowed |
|---------|----------------|
| [qeeqbox/honeypots](https://github.com/qeeqbox/honeypots) | Multi-protocol low-interaction listeners |
| [johnnykv/heralding](https://github.com/johnnykv/heralding) | Credential-catching focus |
| [bjeborn/basic-auth-pot](https://github.com/bjeborn/basic-auth-pot) | Challenge clients for Basic auth |

## Security / legal

- Deploy only on hosts you control.
- Captured passwords are attacker-submitted probe data — do not use them to attack third parties.
- Public Web without TLS is a known tradeoff; prefer localhost + tunnel or reverse proxy TLS.
- MIT License — see [LICENSE](LICENSE).

## License

MIT — see [LICENSE](LICENSE).
