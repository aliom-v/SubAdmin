# SubAdmin

一个可自托管的订阅管理项目，包含：

- Go 后端 API（登录、上游 CRUD、节点 CRUD、同步、输出、备份）
- React 管理后台（`/admin`）
- SQLite 持久化
- Subconverter/Sublink 容器集成
- Caddy 反向代理与 HTTPS

支持两种部署模式：

- 共存模式（推荐给已在主机跑 233boy/sing-box 脚本的场景）：不启用本项目 Caddy，不占用 80/443
- 网关模式：启用本项目 Caddy，统一提供 `/admin`、`/api`、`/clash`、`/singbox`

## 目录结构

- `backend/`: Go API 服务
- `web/`: React 管理后台
- `caddy/`: Caddy 配置
- `docker-compose.yml`: 一键部署
- `项目实现进度.md`: 当前实施与进度主文档

## 快速启动

1. 准备环境变量：

```bash
cp .env.example .env
```

2. 选择启动模式：

### 模式 A：共存模式（不占 80/443）

适用于你已经在 VPS 主机上运行 233boy/sing-box 脚本，并且 80/443 可能已被占用。

```bash
docker compose up -d --build api web sublink
```

默认端口（可在 `.env` 调整）：

- Web：`http://<server-ip>:18081`
- API：`http://<server-ip>:18080`
- 固定输出：`http://<server-ip>:18081/clash`、`http://<server-ip>:18081/singbox`

常用超时参数（可在 `.env` 调整）：

- `API_TIMEOUT_SECONDS`：API 请求超时（默认 `300` 秒）。
- `HTTP_TIMEOUT_SECONDS`：单个上游 HTTP 拉取超时（默认 `20` 秒）。
- `SCHEDULER_JOB_TIMEOUT_SECONDS`：定时任务单次执行超时（默认 `300` 秒）。
- `SUBLINK_SOURCE_BASE_URL`：提供给 `sublink` 拉取临时订阅内容的 API 地址（Docker 默认 `http://api:8080`）。

### 模式 B：网关模式（启用 Caddy）

```bash
docker compose --profile gateway up -d --build
```

访问：

- 管理后台：`https://<your-domain>/admin`
- Clash 输出：`https://<your-domain>/clash`
- Sing-box 输出：`https://<your-domain>/singbox`

本地测试可用 `DOMAIN=localhost`。

## 默认账号

- 用户名：`admin`
- 密码：`admin123`

请在 `.env` 中修改 `ADMIN_PASSWORD` 和 `JWT_SECRET`。

## 后端 API 概览

- 认证：
  - `POST /api/login`
  - `POST /api/logout`
  - `GET /api/me`
  - `PUT /api/password`
  - `GET /api/tokens`
  - `POST /api/tokens`
  - `DELETE /api/tokens/{id}`
- 上游：
  - `GET /api/upstreams`
  - `POST /api/upstreams`
  - `PUT /api/upstreams/{id}`
  - `DELETE /api/upstreams/{id}`
  - `POST /api/upstreams/{id}/sync`
  - `GET /api/upstreams/{id}/raw`
  - `POST /api/upstreams/{id}/raw/preview`
  - `PUT /api/upstreams/{id}/raw`
  - `POST /api/sync`
- 手动节点：
  - `GET /api/nodes`
  - `POST /api/nodes`
  - `PUT /api/nodes/{id}`
  - `DELETE /api/nodes/{id}`
- 设置：
  - `GET /api/settings`
  - `PUT /api/settings`
- 备份：
  - `GET /api/backup/export`
  - `GET /api/backup/sqlite`
  - `POST /api/backup/import`
  - `GET /api/snapshots`
  - `POST /api/snapshots/{id}/rollback`
- 日志：
  - `GET /api/logs/sync`
  - `GET /api/logs/system`
- 固定输出：
  - `GET /clash`
  - `GET /singbox`

## 实现说明

- 默认启用缓存模式：定时同步上游并写入本地缓存文件，再提供固定输出。
- 关闭缓存模式后，访问 `/clash`、`/singbox` 时实时拉取上游并转换。
- 转换对齐官方 `subconverter` 的 `/sub` API；为避免大订阅触发 `414 URI Too Long`，后端会使用一次性临时源 URL 中转节点内容。
- 当 `SUBLINK_URL` 不可用或转换失败时，接口会返回明确错误，便于排障。
- 上游订阅应返回 URI/base64 节点内容；若填入完整 Clash/Sing-box YAML 配置地址，系统会判定为“无可用节点”。
- 上游支持“原始订阅内容预览/粘贴编辑”（URI/base64），可直接写入该上游缓存并参与输出。
- 原始订阅编辑当前聚焦 URI/base64 文本；YAML/JSON 结构化编辑后续再扩展。
- 支持自动定期备份（JSON + SQLite 快照），可在系统设置中开启并设置间隔与保留份数。
- 自动备份文件默认输出到 `data/backups/`（命名：`backup-<UTC时间>.json/.db`）。
- 支持多 Token 访问控制：每次登录创建独立会话 Token，可在后台查看、新增、吊销；改密会自动吊销其他 Token。
- 支持快照回滚：在备份页查看 `clash/singbox` 快照列表并一键回滚，回滚操作会生成新的回滚快照并写入系统日志。

## 最近修复（2026-02-25）

- 已修复“`sync failed: ... query upstream ... context deadline exceeded`”：
  - API 全局超时由固定值改为可配置（`API_TIMEOUT_SECONDS`）。
  - 定时任务单次执行超时由固定值改为可配置（`SCHEDULER_JOB_TIMEOUT_SECONDS`）。
  - 修复 SQLite 单连接场景下的同步阻塞：先收集上游 ID，再逐个同步，避免 `rows` 持有期间嵌套查询导致卡住。
- 已修复“`convert endpoint status 414`（URI 过长）”：
  - 转换请求改为临时中转 URL 模式，由 API 暴露一次性内部源给 `sublink` 拉取内容，避免超长 query。
  - 新增 `SUBLINK_SOURCE_BASE_URL` 配置，用于指定 `sublink` 访问 API 内部源的地址（默认 `http://api:8080`）。
- 同步链路错误提示已收敛：
  - 上游为完整 YAML/JSON 配置地址时，不再“假成功”，会明确报 `subscription contains no nodes`。
  - 聚合后无可用节点时，会明确报 `no nodes available for conversion`。

## 同步排障建议

- 报错 `sync failed: ... query upstream ... context deadline exceeded`：
  - 确认服务已更新到当前版本并重启 `api` 容器。
  - 检查 `.env` 的 `API_TIMEOUT_SECONDS` 和 `SCHEDULER_JOB_TIMEOUT_SECONDS` 是否过小。
- 报错 `convert endpoint status 414`：
  - 确认已启用本版本（临时中转 URL 修复已包含）。
  - 确认 `SUBLINK_SOURCE_BASE_URL` 可被 `sublink` 容器访问（Docker 默认 `http://api:8080`）。
- 报错 `subscription contains no nodes`：
  - 说明上游内容不是 URI/base64 节点订阅（常见是填了 `clash.yaml`/`singbox.json` 配置文件地址）。
  - 请改成节点订阅链接，或改用“上游原始订阅内容粘贴（URI/base64）”。
- 报错 `no nodes available for conversion`：
  - 当前启用上游和手动节点都没有可识别节点。
  - 先在 `POST /api/upstreams/{id}/sync` 或 `POST /api/sync` 后检查上游 `last_status`，再查看 `GET /api/logs/sync` 与 `GET /api/logs/system`。

## 与主机 sing-box 脚本共存注意事项

- `api` 服务已配置 `host.docker.internal:host-gateway`，容器可访问主机服务。
- 如果你的上游地址写成 `127.0.0.1` 或 `localhost`，容器内无法访问，请改为：
  - 主机域名（推荐），例如 `https://your-domain/sub`
  - 或 `http://host.docker.internal:<port>/...`
- 你当前场景建议直接使用“模式 A 共存模式”。

## 已知限制

- 当前实现聚焦 MVP + 部分增强特性（同步、缓存、备份、系统日志、快照回滚、多 Token）；高级同步策略（覆盖/合并）仍在待办。
- 本环境中未安装 `go` / `npm`，无法在本机执行编译校验，建议通过 Docker 构建验证。
