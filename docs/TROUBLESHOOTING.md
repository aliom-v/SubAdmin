# SubAdmin 排障手册

更新时间：2026-02-25

## 1. 快速自检

```bash
# 1) API 健康检查
curl -fsS http://127.0.0.1:18080/healthz

# 2) 容器状态
docker compose ps

# 3) 最近日志
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

## 3. 网络与容器注意事项

- 容器内 `localhost` 指向容器自身，不是宿主机。
- Docker 部署建议保持 `SUBLINK_SOURCE_BASE_URL=http://api:8080`（默认值）。
- 若必须访问宿主机服务，优先使用 `host.docker.internal:<port>`（或本机可解析域名）。

## 4. 进一步定位

1. 后台查看同步日志：`/api/logs/sync`
2. 后台查看系统日志：`/api/logs/system`
3. 如果需要备份恢复，请参考：`docs/BACKUP_RESTORE.md`
