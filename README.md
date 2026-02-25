# SubAdmin

SubAdmin 是一个面向 Clash / Sing-box 的自托管订阅管理面板。  
它把多个上游订阅与手动节点统一管理，输出固定订阅地址，并提供同步日志、备份恢复与快照回滚能力。

## 它解决的问题

- 多个上游来源分散，难统一维护与去重
- 客户端需要长期稳定的固定输出地址（`/clash`、`/singbox`）
- 出问题时需要可追踪、可回滚、可恢复

## 一键部署（推荐）

前置条件：

- 已安装 Docker 与 Docker Compose

```bash
git clone git@github.com:aliom-v/SubAdmin.git
cd SubAdmin
cp .env.example .env
# 首次部署必须修改以下两项
# ADMIN_PASSWORD=你的强密码
# JWT_SECRET=长度至少16位的随机字符串
docker compose up -d --build api web sublink
```

访问地址（共存模式，不占用 80/443）：

- 管理后台：`http://<server-ip>:18081`
- API 健康检查：`http://<server-ip>:18080/healthz`
- 固定输出：`http://<server-ip>:18081/clash`、`http://<server-ip>:18081/singbox`

快速验收：

```bash
curl -fsS http://127.0.0.1:18080/healthz
docker compose ps
```

## 部署模式

- 共存模式（推荐）：`docker compose up -d --build api web sublink`
- 网关模式（走 80/443）：先在 `.env` 设置 `DOMAIN`，再执行 `docker compose --profile gateway up -d --build`

网关模式访问：

- 管理后台：`https://<your-domain>/admin`
- Clash 输出：`https://<your-domain>/clash`
- Sing-box 输出：`https://<your-domain>/singbox`

## 关键配置（同步相关）

- `API_TIMEOUT_SECONDS`：API 请求总超时（默认 `300`）
- `SCHEDULER_JOB_TIMEOUT_SECONDS`：调度任务超时（默认 `300`）
- `HTTP_TIMEOUT_SECONDS`：单上游拉取超时（默认 `20`）
- `SUBLINK_SOURCE_BASE_URL`：`sublink` 拉取临时中转源地址（默认 `http://api:8080`）

## 使用边界

- 上游输入应为 URI/base64 节点订阅，不是完整 `yaml/json` 配置文件。
- 容器内访问主机服务不能用 `127.0.0.1/localhost`，应使用域名或 `host.docker.internal:<port>`。

## 文档

- 排障手册：`docs/TROUBLESHOOTING.md`
- 备份恢复：`docs/BACKUP_RESTORE.md`
- 项目实现进度：`项目实现进度.md`
- 前后端源码：`backend/`、`web/`

## License

MIT
