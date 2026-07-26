# 阶段总览

| 阶段 | 名称 | 目标 | 文档 |
|------|------|------|------|
| Phase 0 | 文档与骨架 | 架构、阶段拆分、仓库结构、依赖 | 本目录 + `../architecture.md` |
| Phase 1 | 可采数 | 多端口蜜罐 L1、JSONL+SQLite、限连、CLI | [phase1-collect.md](./phase1-collect.md) |
| Phase 2 | 可观测 | Web Session、看板、动态端口、导出 | [phase2-web.md](./phase2-web.md) |
| Phase 3 | 长期运营 | L2 开关打磨、轮转备份、告警、reindex | [phase3-ops.md](./phase3-ops.md) |

## 依赖关系

```text
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3
              │            │
              └─ 核心采集 ─┴─ Web 与端口管理
```

## 非目标（全阶段）

- L3 真实代理转发
- FTP/21 等非代理协议
- 强制公网 TLS（可后续加反代，不阻塞主线）
