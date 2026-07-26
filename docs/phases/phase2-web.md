# Phase 2 — 可观测（Web + 动态端口）

## 目标

登录后在线查看采集情况，并支持运行时新增/停用蜜罐端口。

## 完成标准（DoD）

- [x] `WEB_ENABLED` / `WEB_BIND` / `WEB_AUTH_USER` / `WEB_PASSWORD` / `WEB_SESSION_SECRET`
- [x] Session 登录；未登录无法访问 API 与页面
- [x] 登录失败限速（次数 + 临时封禁）
- [x] Dashboard：今日/7 日连接、认证、独立 IP（基础卡片）
- [x] Credentials 列表（Top 聚合）
- [x] Sources（IP）列表：端口与认证次数
- [x] Events：最近事件流
- [x] Ports：列表状态；**新增端口**；启用/停用并真正 listen/close
- [x] 动态端口写入 SQLite，进程重启后恢复
- [x] 与 Phase 1 同进程 `honeypot run` 拉起
- [ ] Credentials 筛选/排序 UI 增强、页面内一键导出（可用 CLI `export` 暂代）

## 任务清单

### 2.1 鉴权

- [x] 登录表单 + Session Cookie
- [x] 密码校验（明文 env 第一版；可预留 hash）
- [x] 失败计数与 ban

### 2.2 API

- [x] `GET /api/stats/summary`
- [x] `GET /api/credentials`
- [x] `GET /api/sources`
- [x] `GET /api/events`
- [x] `GET /api/ports` / `POST /api/ports` / `POST /api/ports/{port}/enable|disable`
- [x] `GET /api/system`

### 2.3 前端

- [x] 服务端 Jinja2 模板
- [x] 基础表格与数字卡片

### 2.4 端口管理集成

- [x] `PortManager`：start_listener / stop_listener
- [x] 与 `ports` 表同步
- [x] 绑定失败错误回传 Web

## 本阶段不做

- TLS 强制
- ASN/GeoIP
- 复杂图表库可选用极简实现
- 多用户 RBAC

## 验收

```bash
set WEB_ENABLED=true
set WEB_BIND=0.0.0.0:8787
set WEB_AUTH_USER=admin
set WEB_PASSWORD=change-me-long-random
set WEB_SESSION_SECRET=another-long-random
python -m honeypot run
# 浏览器登录 → 查看 stats → 新增端口 → 用客户端打该端口 → 列表出现 auth
```
