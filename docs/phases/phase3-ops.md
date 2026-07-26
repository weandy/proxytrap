# Phase 3 — 长期运营

## 目标

作为长期业务稳定跑：数据可重建、可备份、可告警、L2 可实验，运维成本可控。

## 完成标准（DoD）

- [x] JSONL 保留策略 / 磁盘用量可见（Web System 页 + `honeypot disk` + `/api/system`）
- [x] `honeypot reindex`：从 JSONL 重建 SQLite
- [x] 安全备份说明或脚本（`scripts/backup.sh` + `scripts/backup.ps1`，sqlite3 `.backup`）
- [x] L2 `accept_then_fail` 行为完整可测、默认关闭（`AUTH_MODE` / yaml）
- [x] systemd unit 示例（`deploy/proxy-honeypot.service`）
- [x] 可选：今日/连续 N 小时 auth=0 写警告日志（`AUTH_STALE_WARN_HOURS`）
- [x] 可选：credentials 自动日更导出到 `data/exports/daily-*.txt`（`AUTO_EXPORT_HOURS`）
- [x] 文档：云上安全组与投诉应对（`docs/deploy-cloud.md`）

## 任务清单

### 3.1 数据生命周期

- [x] 事件明细保留天数配置（`EVENTS_RETENTION_DAYS`）
- [x] JSONL 文件保留（`JSONL_RETENTION_DAYS`）
- [x] reindex 工具
- [x] export 增强（按端口、按协议 `--port` / `--protocol`）

### 3.2 伪装 L2

- [x] SOCKS5 假成功 + CONNECT 失败码
- [x] HTTP 假成功 + CONNECT 502 / 其它 403
- [x] 测试与文档说明适用场景（`tests/test_l2_*` + README）

### 3.3 部署

- [x] `deploy/proxy-honeypot.service`
- [x] 环境变量示例 `.env.example`（无真实密钥）
- [x] 备份脚本 `scripts/backup.sh` / `backup.ps1`
- [x] `deploy/README.md` 安装步骤

### 3.4 可观测增强

- [x] 队列长度、丢弃事件计数（pipeline stats + System 页）
- [x] 健康检查：`/healthz`（无鉴权 liveness）、`/api/health`（需登录）

## 本阶段仍不做

- L3 转发
- ELK 等重型栈（除非明确需要）
