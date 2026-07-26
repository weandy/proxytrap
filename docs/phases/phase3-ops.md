# Phase 3 — 长期运营

## 目标

作为长期业务稳定跑：数据可重建、可备份、可告警、L2 可实验，运维成本可控。

## 完成标准（DoD）

- [ ] JSONL 保留策略 / 磁盘用量可见（Web System 页）
- [ ] `honeypot reindex`：从 JSONL 重建 SQLite
- [ ] 安全备份说明或脚本（`sqlite3 .backup` + raw 打包）
- [ ] L2 `accept_then_fail` 行为完整可测、默认同配置关闭
- [ ] systemd unit 示例
- [ ] 可选：今日 auth=0 连续 N 小时写警告日志
- [ ] 可选：credentials 自动日更导出到 `data/exports/`
- [ ] 文档：云上安全组与投诉应对说明（ honeypot 无转发）

## 任务清单

### 3.1 数据生命周期

- [ ] 事件明细保留天数配置
- [ ] reindex 工具
- [ ] export 增强（按端口、按协议）

### 3.2 伪装 L2

- [ ] SOCKS5 假成功 + CONNECT 失败码
- [ ] HTTP 假成功 + CONNECT 502/403
- [ ] 测试与文档说明适用场景

### 3.3 部署

- [ ] `deploy/proxy-honeypot.service`
- [ ] 环境变量示例 `.env.example`（无真实密钥）
- [ ] 备份脚本 `scripts/backup.sh` 或 `.ps1`

### 3.4 可观测增强

- [ ] 队列长度、丢弃事件计数
- [ ] 简单健康检查 endpoint（需鉴权或仅本机）

## 本阶段仍不做

- L3 转发
- ELK 等重型栈（除非明确需要）
