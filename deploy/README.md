# Deploy on Linux (systemd)

## 1. User and paths

```bash
sudo useradd -r -m -d /opt/proxy-honeypot -s /usr/sbin/nologin honeypot || true
sudo mkdir -p /opt/proxy-honeypot /var/lib/proxy-honeypot
# clone or rsync project into /opt/proxy-honeypot
sudo chown -R honeypot:honeypot /opt/proxy-honeypot /var/lib/proxy-honeypot
```

## 2. Install

```bash
cd /opt/proxy-honeypot
sudo -u honeypot python3 -m venv .venv
sudo -u honeypot .venv/bin/pip install -U pip
sudo -u honeypot .venv/bin/pip install -e .
```

## 3. Environment

```bash
sudo -u honeypot cp .env.example .env
sudo chmod 600 /opt/proxy-honeypot/.env
# edit secrets:
#   DATA_DIR=/var/lib/proxy-honeypot
#   CONFIG_PATH=/opt/proxy-honeypot/config/config.example.yaml
#   WEB_PASSWORD=...
#   WEB_SESSION_SECRET=...
#   WEB_BIND=127.0.0.1:8787   # recommended; use SSH tunnel or reverse proxy
```

## 4. systemd

```bash
sudo cp deploy/proxy-honeypot.service /etc/systemd/system/
# adjust User/paths in unit if needed
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-honeypot
sudo systemctl status proxy-honeypot
journalctl -u proxy-honeypot -f
```

Health: `curl -s http://127.0.0.1:8787/healthz`

## 5. Firewall / security group

| Port set | Direction | Who |
|----------|-----------|-----|
| Honeypot proxy ports (1080, 3128, …) | inbound | `0.0.0.0/0` (intentional) |
| Web `8787` | inbound | **your IP only** (or none; SSH tunnel) |
| SSH | inbound | your IP only |

This process **never forwards** client traffic. If a cloud provider flags “open proxy”, keep logs and point them at honeypot design (auth always fails / no dial).

## 6. Backup

```bash
sudo -u honeypot bash /opt/proxy-honeypot/scripts/backup.sh
# or on Windows admin host: scripts/backup.ps1
```

## 7. Reindex after restore

```bash
cd /opt/proxy-honeypot
export $(grep -v '^#' .env | xargs)
.venv/bin/python -m honeypot reindex
```
