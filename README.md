# ProxyTrap

[English](#english) · [中文](#中文)

SOCKS5 / HTTP **proxy authentication honeypot** · 代理认证蜜罐  
Collect brute-force credentials · 采集真实爆破账密  
**Never forwards traffic** · **永不转发（非开放代理）**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-weandy%2Fproxytrap-black)](https://github.com/weandy/proxytrap)

---

## English

### What is this?

ProxyTrap listens on common proxy ports, speaks enough SOCKS5 / HTTP proxy protocol to capture **username/password** attempts, and stores them in **JSONL + SQLite**. Optional **Web UI** (session login), **dynamic ports**, **export**, ops tools, and **AI analysis** (OpenAI / Claude compatible; config in `DATA_DIR`, not `.env`).

**L3 open-proxy forwarding is intentionally not implemented.**

### Features

| Area | Description |
|------|-------------|
| Protocols | SOCKS5 (RFC1929), HTTP proxy (407 + Basic, CONNECT) |
| Deception | L1 `always_fail` (default); L2 `accept_then_fail` (still no dial-out) |
| Storage | Daily JSONL + SQLite aggregates |
| Web | Dashboard, credentials, sources, events, ports, system, **AI** |
| Ops | Retention, `reindex`, `disk`, backup scripts, `/healthz` |
| AI | Smart base URL, multi-compat GPT / Responses / Claude, auto-detect |
| Deploy | One-click `deploy/install.sh` (Linux) |

### Quick start (dev)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env        # set WEB_PASSWORD / WEB_SESSION_SECRET

export DATA_DIR=./data CONFIG_PATH=./config/config.example.yaml
export WEB_ENABLED=true WEB_BIND=127.0.0.1:8787
export WEB_AUTH_USER=admin WEB_PASSWORD=please-change-me
export WEB_SESSION_SECRET=please-change-session-secret

python -m honeypot run
# → http://127.0.0.1:8787
```

```bash
python -m honeypot export --top 1000 --format userpass -o data/exports/wordlist.txt
python -m honeypot reindex
python -m honeypot disk
pytest -q
```

### One-click deploy (Linux server)

```bash
git clone https://github.com/weandy/proxytrap.git
cd proxytrap
sudo bash deploy/install.sh
```

The script installs deps, creates user, venv, random Web password `.env`, systemd unit, and starts the service. Defaults: install `/opt/proxy-honeypot`, data `/var/lib/proxy-honeypot`, Web `0.0.0.0:8787`.

```bash
# Optional
sudo WEB_BIND=127.0.0.1:8787 bash deploy/install.sh
sudo INSTALL_DIR=/opt/proxytrap DATA_DIR=/data/proxytrap bash deploy/install.sh
```

```bash
systemctl status proxy-honeypot
journalctl -u proxy-honeypot -f
curl -s http://127.0.0.1:8787/healthz
```

**Security group:** honeypot ports may be open to the world; **restrict Web (8787) and SSH** to your IP. Prefer `WEB_BIND=127.0.0.1:8787` + SSH tunnel.

Windows dev helper: `.\deploy\install.ps1`

### CLI

| Command | Purpose |
|---------|---------|
| `honeypot run` | Start honeypot (+ Web + maintenance) |
| `honeypot export` | Export wordlist (`--port` / `--protocol`) |
| `honeypot reindex` | Rebuild SQLite from JSONL |
| `honeypot disk` | Data directory usage |

### Configuration

- **Minimal `.env`**: path + Web password — see [.env.example](.env.example)
- **Ports**: [config/config.example.yaml](config/config.example.yaml)
- **AI**: Web → **AI** page → saved as `DATA_DIR/ai_settings.json`

| Env | Meaning |
|-----|---------|
| `AUTH_MODE` | `always_fail` \| `accept_then_fail` |
| `EVENTS_RETENTION_DAYS` | SQLite event retention (`0`=off) |
| `JSONL_RETENTION_DAYS` | JSONL file retention (`0`=off) |

### L1 / L2 / L3

| Mode | Behavior |
|------|----------|
| L1 `always_fail` | Auth always fails (default, best for dictionaries) |
| L2 `accept_then_fail` | Fake auth OK, then CONNECT fails — **no outbound** |
| L3 forward | **Not supported** |

### Docs & license

- [docs/](docs/) · [deploy/README.md](deploy/README.md) · [docs/deploy-cloud.md](docs/deploy-cloud.md)
- MIT — [LICENSE](LICENSE)
- Deploy only on hosts you control. Do not use captured credentials against third parties.

---

## 中文

### 这是什么？

ProxyTrap 在常见代理端口上提供 **SOCKS5 / HTTP 代理认证蜜罐**，完整走到认证路径以采集扫描器/爆破的 **用户名与密码**，写入 **JSONL + SQLite**。可选 **Web 看板**（Session 登录）、**动态端口**、密码本导出、运维能力，以及 **AI 对话分析**（兼容 OpenAI / Claude；配置存在 `DATA_DIR`，不写进 `.env`）。

**明确不做 L3：永不转发流量，不是开放代理。**

### 功能一览

| 模块 | 说明 |
|------|------|
| 协议 | SOCKS5（RFC1929）、HTTP 代理（407 + Basic、CONNECT） |
| 伪装 | 默认 L1 认证失败；可选 L2 假成功后业务失败（仍不出站） |
| 存储 | 按日 JSONL + SQLite 聚合 |
| Web | 仪表盘、账密、来源 IP、事件、端口、系统、**AI** |
| 运维 | 保留策略、`reindex`、磁盘统计、备份、`/healthz` |
| AI | Base URL 智能补全，GPT / Responses / Claude 多兼容与自探测 |
| 部署 | Linux 一键 `deploy/install.sh` |

### 本地开发快速启动

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # 修改 WEB_PASSWORD / WEB_SESSION_SECRET

# Windows 可用 set；Linux/macOS:
export DATA_DIR=./data CONFIG_PATH=./config/config.example.yaml
export WEB_ENABLED=true WEB_BIND=127.0.0.1:8787
export WEB_AUTH_USER=admin WEB_PASSWORD=please-change-me
export WEB_SESSION_SECRET=please-change-session-secret

python -m honeypot run
# 浏览器打开 http://127.0.0.1:8787
```

```bash
python -m honeypot export --top 1000 --format userpass -o data/exports/wordlist.txt
python -m honeypot reindex
python -m honeypot disk
pytest -q
```

### 一键部署（Linux 服务器 · 推荐）

```bash
git clone https://github.com/weandy/proxytrap.git
cd proxytrap
sudo bash deploy/install.sh
```

脚本会：装系统依赖 → 创建用户 → 同步到 `/opt/proxy-honeypot` → venv 安装 → 生成随机 Web 密码的 `.env` → 安装 systemd 并启动。

| 项 | 默认 |
|----|------|
| 安装目录 | `/opt/proxy-honeypot` |
| 数据目录 | `/var/lib/proxy-honeypot` |
| Web | `0.0.0.0:8787` |
| 服务名 | `proxy-honeypot` |

```bash
# Web 仅本机（更安全，配合 SSH 隧道）
sudo WEB_BIND=127.0.0.1:8787 bash deploy/install.sh

# 自定义路径
sudo INSTALL_DIR=/opt/proxytrap DATA_DIR=/data/proxytrap bash deploy/install.sh

# 只安装不启动
sudo SKIP_START=1 bash deploy/install.sh
```

```bash
systemctl status proxy-honeypot
journalctl -u proxy-honeypot -f
curl -s http://127.0.0.1:8787/healthz
sudo -u honeypot bash /opt/proxy-honeypot/scripts/backup.sh
```

浏览器访问 `http://<服务器IP>:8787`，用安装输出的账号密码登录；在 **Ports / AI** 中按需配置。

**云安全组建议：**

- 蜜罐代理端口（1080、3128、7890…）可对公网开放  
- **Web 8787 与 SSH 仅放行你的管理 IP**（或 Web 绑 `127.0.0.1`）

更细说明：[docs/deploy-cloud.md](docs/deploy-cloud.md) · 手工步骤：[deploy/README.md](deploy/README.md)

Windows 本机准备：`.\deploy\install.ps1`

### 命令行

| 命令 | 作用 |
|------|------|
| `honeypot run` | 启动蜜罐（+ Web + 维护循环） |
| `honeypot export` | 导出密码本（支持 `--port` / `--protocol`） |
| `honeypot reindex` | 从 JSONL 重建 SQLite |
| `honeypot disk` | 查看数据目录占用 |

### 配置说明

- **`.env` 尽量精简**：数据路径 + 管理页密码 — 见 [.env.example](.env.example)  
- **端口列表**： [config/config.example.yaml](config/config.example.yaml)  
- **AI**：Web → **AI** 页配置，保存为 `DATA_DIR/ai_settings.json`

| 环境变量 | 含义 |
|----------|------|
| `AUTH_MODE` | `always_fail`（默认）\| `accept_then_fail` |
| `EVENTS_RETENTION_DAYS` | 事件保留天数，`0` 关闭 |
| `JSONL_RETENTION_DAYS` | JSONL 保留天数，`0` 关闭 |

### L1 / L2 / L3

| 模式 | 行为 |
|------|------|
| L1 认证失败 | 默认；适合持续收字典 |
| L2 假成功 | 认证“成功”后 CONNECT 仍失败，**无出站** |
| L3 真转发 | **不支持、不实现** |

### 安全与许可

- 仅部署在你有权控制的主机上  
- 采集到的账密为攻击者主动提交的探测数据，勿用于对外撞库  
- 公网 Web 无 TLS 有风险；生产建议本机绑定 + 隧道或反代 HTTPS  
- MIT 协议 — [LICENSE](LICENSE)

---

**Repo:** https://github.com/weandy/proxytrap  
