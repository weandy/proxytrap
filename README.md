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
| AI | Web **AI**: smart base URL, multi-compat **OpenAI chat / Responses / Claude**, auto-detect, chat + presets; config → `data/ai_settings.json` |
| Deploy | **一键** `deploy/install.sh`（Linux）/ `install.ps1`（Windows 开发）, systemd, backup scripts |

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

## 一键部署（推荐 · Linux 服务器）

适用于 Ubuntu / Debian / 常见云主机（systemd）。在**已克隆的仓库目录**执行：

```bash
# 1) 上传或克隆代码到服务器后
cd /path/to/proxy-honeypot   # 或本仓库 miguan

# 2) 一键安装（自动：依赖、用户、venv、.env 随机密码、systemd、启动）
sudo bash deploy/install.sh
```

装完脚本会打印 **Web 地址 / 用户名 / 随机密码**。默认：

| 项 | 默认 |
|----|------|
| 安装目录 | `/opt/proxy-honeypot` |
| 数据目录 | `/var/lib/proxy-honeypot` |
| Web | `0.0.0.0:8787`（可用环境变量改） |
| 服务名 | `proxy-honeypot` |

### 常用可选参数

```bash
# Web 仅本机（更安全，配合 SSH 隧道）
sudo WEB_BIND=127.0.0.1:8787 bash deploy/install.sh

# 自定义路径
sudo INSTALL_DIR=/opt/miguan DATA_DIR=/data/miguan bash deploy/install.sh

# 只安装不启动
sudo SKIP_START=1 bash deploy/install.sh
```

### 装完后

```bash
# 状态 / 日志
systemctl status proxy-honeypot
journalctl -u proxy-honeypot -f

# 本机健康检查
curl -s http://127.0.0.1:8787/healthz

# 备份
sudo -u honeypot bash /opt/proxy-honeypot/scripts/backup.sh
```

浏览器打开 `http://<服务器IP>:8787` → 用安装输出的账号密码登录 → **Ports / AI** 按需配置。

**云安全组：**

- 蜜罐代理端口（1080、3128、7890…）：可对 `0.0.0.0/0`
- **Web 8787 / SSH：只放行你的办公 IP**（或 Web 绑 `127.0.0.1` + SSH 隧道）

> 本服务**永不转发**流量，不是开放代理。说明见 [docs/deploy-cloud.md](docs/deploy-cloud.md)。

### 从 Git 拉代码再一键装（示例）

```bash
git clone https://github.com/weandy/proxy-auth-honeypot.git
cd proxy-auth-honeypot
sudo bash deploy/install.sh
```

### Windows 本机一键准备（开发）

```powershell
# 仓库根目录
.\deploy\install.ps1
.\.venv\Scripts\python.exe -m honeypot run
# 浏览器 http://127.0.0.1:8787
```

### 手工部署（逐步）

详见 **[deploy/README.md](deploy/README.md)**。

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
