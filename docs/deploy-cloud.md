# 云上部署与投诉应对

## 安全组建议

| 流量 | 建议 |
|------|------|
| 蜜罐代理端口 | 入站 `0.0.0.0/0`（故意暴露） |
| Web 管理口 | 仅管理 IP，或绑定 `127.0.0.1` + SSH 隧道 / 反代 |
| SSH | 仅管理 IP |
| 出站 | 无需为「代理业务」开特殊策略；本服务不转发客户流量 |

## 本服务不是开放代理

- 认证默认 **always_fail**；可选 L2 假成功后业务仍失败
- 代码路径中 **无** `open_connection` / 上游 dial / 双向中继
- 日志可证明：只有握手与认证失败，没有成功隧道

若云厂商误报 open proxy：

1. 提供进程说明与仓库 README / 本文件  
2. 提供近期 JSONL / SQLite 中仅有 auth fail 的样例  
3. 确认安全组未另外部署真代理  
4. 可将 Web 与管理面进一步收敛，仅保留蜜罐口公网

## 数据与合规

- 仅记录主动连入并提交的凭证与扫描元数据  
- 勿将采集密码用于对外撞库  
- 部署在你有权控制的主机上  

## 运维命令摘要

```bash
python -m honeypot run
python -m honeypot export --top 1000 --format userpass -o data/exports/wl.txt
python -m honeypot export --port 1080 --protocol socks5
python -m honeypot reindex
python -m honeypot disk
bash scripts/backup.sh
```
