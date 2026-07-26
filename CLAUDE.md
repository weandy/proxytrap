# Proxy Auth Honeypot (miguan)

## 项目目标

长期运行的 SOCKS5 / HTTP(S CONNECT) **代理认证蜜罐**：采集扫描与爆破使用的用户名密码，沉淀按端口/协议维度的密码本；提供 Web 观测与动态端口管理。

## 硬性约束

- **永不转发**：不实现任何 upstream dial / 流量中继（禁止 L3）
- 默认认证策略 **L1 always_fail**；可选 **L2 accept_then_fail**（假成功后业务失败）
- 密钥与 Web 口令只走环境变量，不进仓库、不进 JSONL
- 改完跑验证：见下方「验证」

## 技术栈

- Python 3.11+
- asyncio 蜜罐监听
- SQLite + JSONL
- FastAPI + Session 登录（暂不强制 TLS）
- 配置：YAML 端口表 + 环境变量覆盖

## 目录约定

```text
docs/           架构与阶段文档
src/honeypot/   业务代码
config/         示例配置（无密钥）
data/           运行时数据（gitignore）
tests/          测试
scripts/        运维脚本
```

## 命名

- 模块/文件：snake_case
- 类：PascalCase
- 环境变量：`HONEYPOT_*` / `WEB_*` / `DATA_DIR` 等（见 config 示例与 README）

## 验证

```bash
cd <repo>
python -m pip install -e ".[dev]"
python -m pytest -q
python -m honeypot --help
```

## 红线（必须先问用户）

- 删除数据目录或 git 历史
- 实现真实代理转发（L3）
- 把 Web 口令写入代码仓库
- 公网部署密钥/CI 变更
