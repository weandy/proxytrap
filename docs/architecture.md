# 整体架构

## 1. 目标

在海外云主机长期运行，对一组常见代理端口提供 **SOCKS5 / HTTP 代理（含 CONNECT）认证蜜罐**：

- 记录扫描 IP、端口、协议、认证账密
- JSONL 原始账本 + SQLite 可查询聚合
- Web 公网可访问（Session 用户名密码），支持观测与 **动态新增/停用蜜罐端口**
- **永不转发流量（禁止 L3）**

## 2. 逻辑架构

```text
                     公网
                       │
         ┌─────────────┼──────────────────┐
         │             │                  │
    蜜罐端口组      Web 端口            SSH
   (可动态增减)   (Session 鉴权)      (管理 IP)
         │             │
         ▼             ▼
  ┌────────────┐  ┌─────────────┐
  │ Honeypot   │  │ Web (FastAPI)│
  │ Engine     │  │ 只读+端口管理 │
  └─────┬──────┘  └──────┬──────┘
        │                │
        ▼                ▼
  ┌─────────────────────────────┐
  │ Ingest                       │
  │  Event → JSONL append        │
  │       → SQLite insert/upsert │
  └─────────────────────────────┘
        │
        ▼
   data/raw/events-YYYY-MM-DD.jsonl
   data/honeypot.db
```

可同进程运行（`honeypot run` 同时起蜜罐 + Web），也支持后续拆分为独立进程（共享 DB）。

## 3. 协议与伪装

| 级别 | 行为 | 本项目 |
|------|------|--------|
| L1 always_fail | 完整握手，认证失败，记账密 | **默认** |
| L2 accept_then_fail | 认证“成功”，CONNECT/命令失败 | 可配置 |
| L3 真转发 | dial + 中继 | **禁止，不实现** |

### 3.1 端口策略：primary + 首包检测

每个监听端口配置：

- `primary`：期望协议（`socks5` / `http_proxy`）
- `also_accept`：首包像其他协议时是否继续处理
- `enabled`：是否监听

首包指纹：

- `0x05` → SOCKS5
- HTTP method 行 → HTTP 代理
- 其他 → `probe` / `unknown` 记录后断开

落库同时写 `configured_primary` 与 `detected_protocol`，便于清洗。

### 3.2 SOCKS5

1. Greeting → 优先选 method `0x02`（用户名密码）
2. 无 `0x02` → 拒绝并记录 `no_userpass_offered`
3. RFC1929 解析 username/password 并记录
4. L1：认证失败 `0x01`；L2：认证成功后对 CONNECT 返回失败
5. 不进入成功转发路径

### 3.3 HTTP / CONNECT

1. 无 `Proxy-Authorization` → `407` + `Proxy-Authenticate: Basic realm="..."`
2. 有 Basic → 解码记录，再 407/403 或 L2 下假成功但 CONNECT 失败
3. `CONNECT` 标记为 `https_connect` 语义（仍不建隧道）

## 4. 数据层

### 4.1 JSONL（source of truth）

- 路径：`{DATA_DIR}/raw/events-YYYY-MM-DD.jsonl`
- 一行一个 JSON 事件，append-only
- 可按天轮转；支持 `reindex` 重建 SQLite

### 4.2 SQLite（查询投影）

主要表：

| 表 | 用途 |
|----|------|
| `events` | 近原始事件，索引 ip/port/type/ts |
| `credentials` | user+pass 聚合（count、ports、protocols） |
| `sources` | 源 IP 画像 |
| `port_stats_daily` | 按日端口统计 |
| `ports` | 动态端口配置与状态 |
| `meta` | schema 版本等 |

### 4.3 事件最小字段

```text
ts, event_id, conn_id, src_ip, src_port, dst_port,
configured_primary, detected_protocol, event_type,
username, password, auth_scheme,
http_method, http_target, tls,
client_first_bytes_hex, extra
```

`event_type`：`connect` | `probe` | `negotiate` | `auth` | `reject` | `timeout` | `error`

## 5. 写入路径

```text
Handler → 有界 Queue → Writer
  1) append JSONL
  2) INSERT events
  3) UPSERT credentials / sources / daily stats
```

队列满时优先保留 `auth` 事件策略（实现可配置）。

## 6. Web

- FastAPI + Session Cookie（`HttpOnly`, `SameSite=Lax`）
- 环境变量：`WEB_AUTH_USER`, `WEB_PASSWORD` / hash, `WEB_SESSION_SECRET`, `WEB_BIND`
- 登录失败限速
- 页面：Dashboard / Credentials / Sources / Events / Ports / System
- 端口 API：列表、新增、启用/停用（需登录）
- 阶段 1 可不强制 TLS（明文风险自担）

## 7. 配置

| 来源 | 内容 |
|------|------|
| 环境变量 | 密钥、绑定、DATA_DIR、AUTH_MODE、Web 开关 |
| YAML | 初始端口列表、协议 primary、伪装 header/realm |
| SQLite `ports` | 运行时新增端口，重启恢复 |

## 8. 进程与部署

- 入口：`python -m honeypot run`
- 海外 VPS；安全组放行蜜罐端口；SSH 限制来源
- 建议 systemd 托管；数据目录定期备份
- 限连：`max_conns_global` / `max_conns_per_ip`

## 9. 模块划分

```text
src/honeypot/
  __main__.py          CLI
  config.py            环境变量 + YAML
  models.py            事件与数据结构
  detect.py            首包协议检测
  proto/
    socks5.py
    http_proxy.py
  server.py            多端口监听与连接调度
  port_manager.py      动态端口启停
  sink/
    jsonl.py
    sqlite.py
    pipeline.py        统一写入
  web/
    app.py
    auth.py
    routes.py
    templates/ 或 static/
  limits.py
  export.py            密码本导出
```

## 10. 安全边界

1. 代码路径不存在 forwarding
2. Web 管理接口全部鉴权
3. 不暴露 `data/raw` 静态目录
4. 凭证仅本地分析，不用于对外撞库
