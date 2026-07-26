# Proxy Auth Honeypot (miguan)

SOCKS5 / HTTP 代理 **认证蜜罐**：采集爆破账密，JSONL + SQLite 存储，Web Session 观测与动态端口管理。

**永不转发流量（禁止开放代理 / L3）。**

## 文档

| 文档 | 说明 |
|------|------|
| [docs/requirements.md](docs/requirements.md) | 需求冻结 |
| [docs/architecture.md](docs/architecture.md) | 整体架构 |
| [docs/phases/README.md](docs/phases/README.md) | 阶段总览 |
| [docs/phases/phase1-collect.md](docs/phases/phase1-collect.md) | Phase 1 可采数 |
| [docs/phases/phase2-web.md](docs/phases/phase2-web.md) | Phase 2 Web |
| [docs/phases/phase3-ops.md](docs/phases/phase3-ops.md) | Phase 3 运营 |

## 快速开始

```bash
cd miguan
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux
# source .venv/bin/activate

pip install -e ".[dev]"
copy .env.example .env   # 并修改 WEB_PASSWORD / WEB_SESSION_SECRET

# 建议先用少量端口测试：可编辑 config 或仅开 Web 后在页面加端口
set DATA_DIR=./data
set CONFIG_PATH=./config/config.example.yaml
set WEB_ENABLED=true
set WEB_BIND=127.0.0.1:8787
set WEB_AUTH_USER=admin
set WEB_PASSWORD=please-change-me
set WEB_SESSION_SECRET=please-change-session-secret

python -m honeypot run
```

浏览器打开 `http://127.0.0.1:8787`，登录后查看 Dashboard / Credentials / Ports。

导出密码本：

```bash
python -m honeypot export --top 1000 --format userpass -o data/exports/wordlist.txt
```

## 环境变量

见 [.env.example](.env.example)。密钥不要提交仓库。

## 验证

```bash
pytest -q
python -m honeypot --help
```

## 安全说明

- 认证默认 `always_fail`，可选 `accept_then_fail`（假成功后业务失败，仍不出站）
- Web 当前可不启用 TLS（公网明文有风险，自行权衡）
- 云主机请限制 SSH 来源；蜜罐端口可对公网开放
- 本服务 **不能** 作为可用代理上网

## 相关开源思路（参考，非 fork）

| 项目 | 可借鉴点 |
|------|----------|
| [qeeqbox/honeypots](https://github.com/qeeqbox/honeypots) | 多协议低交互监听，含 socks5 / httpproxy |
| [johnnykv/heralding](https://github.com/johnnykv/heralding) | 以抓认证凭证为核心，不做真实业务后端 |
| [bjeborn/basic-auth-pot](https://github.com/bjeborn/basic-auth-pot) | 用挑战响应诱导 Basic 账密 |

本项目对齐其「走完认证路径并记录」的思路，**明确不做** 开放代理 / 流量转发（L3）。

## 许可与用途

仅用于自有主机上的防御性观测与密码本情报收集。勿用于攻击他人服务。
