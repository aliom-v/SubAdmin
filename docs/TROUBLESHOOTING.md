# SubAdmin 排障手册

更新时间：2026-03-02

## 1. 快速自检

```bash
# 1) API 健康检查
curl -fsS http://127.0.0.1:18080/healthz

# 2) 指标端点检查
curl -fsS http://127.0.0.1:18080/metrics | head

# 3) 容器状态
docker compose ps

# 4) 最近日志
docker compose logs --tail=200 api
docker compose logs --tail=200 sublink
```

如果是网关模式，请把 `127.0.0.1:18080` 换成你的网关入口地址。

## 2. 常见错误

### 2.1 `query upstream ... context deadline exceeded`

常见原因：

- 上游地址不可达或响应很慢
- 超时参数过小
- 容器网络配置错误（例如容器内用了 `localhost` 指向自己）

处理建议：

1. 确认上游 URL 可达，并可在服务器侧直接访问。
2. 在 `.env` 增大以下参数后重启：
   - `API_TIMEOUT_SECONDS`（默认 300）
   - `SCHEDULER_JOB_TIMEOUT_SECONDS`（默认 300）
   - `HTTP_TIMEOUT_SECONDS`（默认 20）
3. 若上游服务部署在宿主机，容器中不要用 `127.0.0.1/localhost`，改用 `host.docker.internal:<port>` 或可解析域名。

### 2.2 `convert endpoint status 414`

常见原因：

- 旧版本将大订阅内容直接拼到 query，触发 URI 过长
- `SUBLINK_SOURCE_BASE_URL` 配置错误，导致临时中转源不可达

处理建议：

1. 使用当前版本（已内置中转源方案）。
2. 检查 `.env`：`SUBLINK_SOURCE_BASE_URL` 在 Docker 默认应为 `http://api:8080`。
3. 重启服务后重试同步：
   ```bash
   docker compose up -d --build api web sublink
   ```

### 2.3 `subscription contains no nodes`

常见原因：

- 上游内容不是 URI/base64 节点订阅，而是完整 YAML/JSON 配置文件
- 返回页面是鉴权页/错误页，不是节点文本

处理建议：

1. 确认上游链接返回的是节点订阅原文，而不是配置面板导出的整份配置。
2. 用原始预览接口检查返回内容是否含有效节点 URI。
3. 如上游需要鉴权，先确认凭据有效再写入 SubAdmin。

### 2.4 `no nodes available for conversion`

常见原因：

- 启用的上游和手动节点汇总后仍为空
- 节点格式不受识别或全部被禁用

处理建议：

1. 检查上游是否启用、最近同步是否成功。
2. 检查手动节点是否启用且 URI 合法。
3. 至少准备一个可识别节点后再触发转换。

### 2.5 `upstream status 429` 或 `upstream status 5xx`

常见原因：

- 上游服务限流（429）或短时故障（5xx）
- 上游服务端负载过高，响应不稳定

处理建议：

1. 先观察系统日志是否出现 `sync_upstream_retry`，确认系统是否已自动重试。
2. 若重试后仍失败，可适度调大以下参数：
   - `SYNC_RETRY_MAX_ATTEMPTS`（默认 3）
   - `SYNC_RETRY_BASE_DELAY_MS`（默认 500）
   - `SYNC_RETRY_MAX_DELAY_MS`（默认 5000）
3. 如上游长期限流，建议降低同步频率或更换上游源。

### 2.6 如何判断“失败隔离”是否生效

现象判定：

- 单个上游失败，但其他上游仍有 `ok` 同步记录，说明失败隔离正常。
- `POST /api/sync` 返回失败时，如果错误详情包含部分上游 ID，通常表示“部分失败但任务未全局阻断”。

排查步骤：

1. 查看同步日志：确认同一轮次中是否同时存在 `ok` 和 `fail` 记录。
2. 查看系统日志：关注 `sync_upstream_retry` 与 `sync_upstream` 的 `class` 字段（如 `timeout`、`upstream_5xx`、`upstream_rate_limited`）。
3. 若全部上游都失败，再回查网络、DNS、上游可达性与超时参数。

## 3. 网络与容器注意事项

- 容器内 `localhost` 指向容器自身，不是宿主机。
- Docker 部署建议保持 `SUBLINK_SOURCE_BASE_URL=http://api:8080`（默认值）。
- 若必须访问宿主机服务，优先使用 `host.docker.internal:<port>`（或本机可解析域名）。

## 4. 进一步定位

1. 后台查看同步日志：`/api/logs/sync`
2. 后台查看系统日志：`/api/logs/system`
3. 如需放大重试容错，检查 `.env`：`SYNC_MAX_CONCURRENCY`、`SYNC_RETRY_MAX_ATTEMPTS`、`SYNC_RETRY_BASE_DELAY_MS`、`SYNC_RETRY_MAX_DELAY_MS`
4. 如果需要备份恢复，请参考：`docs/BACKUP_RESTORE.md`
