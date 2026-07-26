# Phase 1 — 可采数（核心蜜罐）

## 目标

上线后只要进程在跑，就能在配置端口上采集认证尝试，并持久化到 JSONL + SQLite。

## 完成标准（DoD）

- [x] 可从 YAML + 环境变量加载配置
- [x] 多端口并发 `listen`（初始端口列表见配置示例）
- [x] SOCKS5：method 协商 + RFC1929 用户名密码，L1 失败并记录
- [x] HTTP 代理：407 + Basic 解析；支持 CONNECT 标记
- [x] 首包检测：`primary` + `also_accept`
- [x] 每个连接产生 `connect` / `negotiate` / `auth` 等事件
- [x] JSONL 按天写入 `data/raw/`
- [x] SQLite：`events` / `credentials` / `sources` 基本可用
- [x] 全局限连 + 每 IP 限连
- [x] **无任何转发代码路径**
- [x] CLI：`python -m honeypot run` / `export` / `--help`
- [x] 集成测试可打出带 password 的 auth 记录
- [x] `pytest` 覆盖协议解析与写入关键路径

## 任务清单

### 1.1 工程骨架

- [x] `pyproject.toml` / 包结构 `src/honeypot`
- [x] 示例 `config/config.example.yaml`
- [x] `.gitignore`（data、.env、venv）
- [x] README 启动说明

### 1.2 配置

- [x] `DATA_DIR`, `CONFIG_PATH`, `AUTH_MODE`, `HONEYPOT_BIND`
- [x] 限流与超时参数
- [x] 端口列表解析（port / primary / also_accept / enabled）

### 1.3 协议

- [x] `detect.py` 首包指纹
- [x] `proto/socks5.py` 状态机
- [x] `proto/http_proxy.py` 请求解析 + 407/Basic

### 1.4 服务

- [x] `server.py` 多端口 accept 循环
- [x] `limits.py` 连接计数
- [x] 连接 `conn_id`、读超时

### 1.5 存储

- [x] JSONL sink（按日文件）
- [x] SQLite schema + upsert 聚合
- [x] 异步写入 pipeline（队列）

### 1.6 CLI 与测试

- [x] `run` / `export` 子命令
- [x] 单元测试：SOCKS5 auth 帧、HTTP Basic、detect

## 验收命令（示例）

```bash
pip install -e ".[dev]"
pytest -q
set DATA_DIR=./data
set CONFIG_PATH=./config/config.example.yaml
python -m honeypot run
# 另开终端模拟爆破后检查 data/raw 与 sqlite
python -m honeypot export --top 20
```

## 本阶段不做

- Web UI
- 动态加端口 API
- L2 复杂分支可先留配置位，行为以 L1 为主
- TLS 代理口
