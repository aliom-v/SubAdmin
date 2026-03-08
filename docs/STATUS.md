# 项目实施与进度文档

更新时间：2026-03-08（清理模板文档与引用）

## 1. 文档定位

- 本文档用于记录当前可用能力、已完成修复、验收口径和后续待办。
- 目标是让开发、运维和验收都可以基于同一份事实执行。
- 集中的遗留问题与后续优化建议见 `docs/OPEN_ISSUES.md`。
- 策略变更的上线、验证与回滚手册见 `docs/STRATEGY_ROLLOUT.md`。
- Phase 4 回归与验收记录见 `docs/PHASE4_REGRESSION.md`。
- 当前指标与监控说明见 `docs/METRICS.md`。

## 2. 当前结论

- 项目已具备可用 MVP，并已完成多轮稳定性修复。
- 已支持共存部署（默认不占用 80/443），可通过 Docker Compose 直接运行。
- 已完成 P0+O4：Cookie 优先会话、登录限流锁定、输出 ETag/304、同步并发重试隔离。
- 已完成 O5/O6：SQLite 索引补齐与查询计划验证、`subconverter` 镜像 digest 固定。
- 已完成 O7/O8：Prometheus 指标与结构化日志、CI 门禁工作流（后端+前端+冒烟）。
- 已完成最新 Phase 4 回归：`make acceptance` 全量通过（2026-03-08 22:26 +08:00），已形成包含策略接口与策略日志断言的最新本地基线。
- 已补齐单独的 Phase 4 回归记录与指标监控文档。
- 已补齐 Phase 4 压测抽检脚本与 CI 证据产物上传能力。
- 已完成高级同步策略最小闭环：新增策略配置、preview API、管理后台配置入口，并接入输出聚合链路。
- 当前主要待办为按需执行真实压测抽检、在 CI 首次远端运行后补充远端证据产物，并补齐高级同步策略指标与接口级测试。

## 3. 功能状态矩阵

| 模块 | 状态 | 说明 |
|---|---|---|
| 管理后台 | 已完成 | 登录、改密、上游/节点 CRUD、同步触发、设置、日志查询 |
| 认证与会话 | 已完成（增强） | 多 Token 会话管理、吊销、过期校验、改密后吊销其他 Token；Cookie 优先 + Bearer 兼容；登录限流与短时锁定 |
| 上游同步 | 已完成（增强） | 支持多上游、启停、同步间隔、手动+定时同步、同步日志；支持 worker pool 并发、指数退避重试、失败隔离 |
| 订阅输出 | 已完成（增强） | 固定输出 `/clash` `/singbox`，支持缓存模式与实时模式；支持 ETag/If-None-Match/304 |
| 转换链路 | 已完成 | 对齐 `subconverter /sub`，已修复大订阅 `414 URI Too Long` |
| 备份恢复 | 已完成 | JSON 导出/导入、SQLite 导出、自动备份、快照回滚 |
| 日志审计与观测 | 已完成（增强） | `sync_logs` 与 `system_logs`，含 API 查询能力；新增 `/metrics` 指标与结构化 `system_logs.detail` |
| 高级同步策略 | 进行中（最小闭环已完成） | 已支持 `/api/strategy`、`/api/strategy/preview`、管理后台配置与预览；最新本地回归已归档，策略指标、接口级测试与更细粒度策略仍未完成 |

## 4. 已实现 API 范围

认证与会话：

- `POST /api/login`
- `POST /api/logout`
- `GET /api/me`
- `PUT /api/password`
- `GET /api/tokens`
- `POST /api/tokens`
- `DELETE /api/tokens/:id`

上游管理与同步：

- `GET /api/upstreams`
- `POST /api/upstreams`
- `PUT /api/upstreams/:id`
- `DELETE /api/upstreams/:id`
- `POST /api/upstreams/:id/sync`
- `GET /api/upstreams/:id/raw`
- `POST /api/upstreams/:id/raw/preview`
- `PUT /api/upstreams/:id/raw`
- `POST /api/sync`

手动节点：

- `GET /api/nodes`
- `POST /api/nodes`
- `PUT /api/nodes/:id`
- `DELETE /api/nodes/:id`

系统设置与日志：

- `GET /api/settings`
- `PUT /api/settings`
- `GET /api/strategy`
- `PUT /api/strategy`
- `POST /api/strategy/preview`
- `GET /api/logs/sync`
- `GET /api/logs/system`

备份与快照：

- `GET /api/backup/export`
- `GET /api/backup/sqlite`
- `POST /api/backup/import`
- `GET /api/snapshots`
- `POST /api/snapshots/:id/rollback`

固定输出与健康检查：

- `GET /clash`
- `GET /singbox`
- `GET /healthz`
- `GET /metrics`

## 5. 部署模式与关键配置

推荐运行模式：

- 共存模式（推荐）：`docker compose up -d --build api web sublink`
- 网关模式（可选）：`docker compose --profile gateway up -d --build`

关键环境变量：

- `API_TIMEOUT_SECONDS`：API 请求超时（默认 300 秒）
- `SCHEDULER_JOB_TIMEOUT_SECONDS`：定时任务单次执行超时（默认 300 秒）
- `HTTP_TIMEOUT_SECONDS`：单个上游 HTTP 拉取超时（默认 20 秒）
- `SUBLINK_SOURCE_BASE_URL`：供 `sublink` 拉取临时中转源的 API 地址（Docker 默认 `http://api:8080`）
- `SUBLINK_IMAGE`：`sublink` 镜像版本（默认固定 digest：`tindy2013/subconverter@sha256:6db842efdb44bc4c17c9ac05660ed35753e8c195ef105afcba55daceb1ab35bf`）
- `LOGIN_RATE_MAX_IP` / `LOGIN_RATE_MAX_USERNAME`：登录固定窗口限流阈值
- `LOGIN_LOCK_THRESHOLD` / `LOGIN_LOCK_SECONDS`：登录失败锁定阈值与锁定时长
- `OUTPUT_ETAG_ENABLED` / `OUTPUT_CACHE_CONTROL`：输出缓存协商开关与缓存控制头
- `SYNC_MAX_CONCURRENCY`：同步并发上限
- `SYNC_RETRY_MAX_ATTEMPTS`：单上游最大重试次数（含首轮）
- `SYNC_RETRY_BASE_DELAY_MS` / `SYNC_RETRY_MAX_DELAY_MS`：重试退避基准与最大延迟

## 6. 同步链路现状（重点）

当前同步主流程：

1. 读取启用上游并触发拉取。
2. 解析上游内容为节点 URI（并去重）。
3. 写回上游缓存与同步状态。
4. 聚合节点后调用 `subconverter` 生成 Clash/Sing-box 输出。
5. 缓存模式下写入本地缓存文件并生成快照。

本轮关键修复（已落地）：

- 修复 `context deadline exceeded`：
  - API 超时和调度任务超时改为可配置。
- 修复 SQLite 单连接下同步阻塞：
  - 改为先收集上游 ID，再逐个同步，避免 `rows` 占用期间嵌套查询。
- 修复 `convert endpoint status 414`：
  - 增加临时中转源 URL，不再把大 payload 直接放进 query。
- 修复“假成功同步”：
  - 仅识别合法节点 URI 协议行，非节点格式内容会明确失败。
- 完成 O4 同步稳定性增强：
  - 同步任务改为 worker pool 并发执行（可配置并发上限）。
  - 单上游支持指数退避重试（可配置重试次数与退避延迟上限）。
  - 单上游失败不阻断其他上游继续同步，并记录失败分类与重试次数。

当前错误语义（用于排障）：

- `query upstream ... context deadline exceeded`：通常是旧版本或超时参数过小。
- `convert endpoint status 414`：通常是旧版本未使用中转源。
- `subscription contains no nodes`：上游不是 URI/base64 节点订阅（常见是 YAML/JSON 完整配置地址）。
- `no nodes available for conversion`：启用上游与手动节点聚合后无可识别节点。
- `upstream status 429/5xx`：上游限流或服务端异常，系统会按退避策略自动重试。
- 系统日志 `sync_upstream_retry`：表示触发了可恢复错误重试，可结合 `class` 字段判断失败类型。

## 7. 验收清单（建议）

基础可用性：

- `GET /healthz` 返回 `{"status":"ok"}`。
- `POST /api/login` 成功后可访问受保护接口（Cookie 会话）。
- 新增一个手动 URI 节点后，`/clash` 可成功输出。

同步链路：

- 有效 URI/base64 上游同步后，`last_status` 显示 `ok (...)`。
- 非节点格式上游（如完整 YAML/JSON 配置）同步后，`last_status` 明确失败为 `subscription contains no nodes`。
- 存在慢/坏上游时，其它上游仍可继续完成同步（失败隔离生效）。

备份与回滚：

- `GET /api/backup/export` 可导出 JSON。
- `GET /api/backup/sqlite` 可下载 `.db`。
- 快照回滚后，输出缓存和系统日志可见对应记录。

## 8. 已知边界与限制

- 当前上游输入期望为 URI/base64 节点订阅，不是完整配置文件编辑器。
- 高级同步策略已具备 API、管理后台最小配置能力、独立运维手册与最新本地回归基线，但策略指标、更细粒度策略与接口级测试仍待补充。
- 本地无 Go/NPM 时，建议通过 Docker 构建验证。

## 9. 下一阶段计划

P0（优先）：

1. 已完成 O5：SQLite 索引优化与查询计划验证（`EXPLAIN QUERY PLAN`）。
2. 已完成 O6：固定 `subconverter` 镜像版本（digest）并同步配置文档。

P1（增强）：

1. 已完成 O7：Prometheus 指标与结构化日志规范。
2. 已完成 O8：CI 门禁（后端测试 + 前端构建 + 接口冒烟）。
3. 已完成高级同步策略最小闭环，下一步补齐接口级测试、策略指标与更细粒度策略能力。

下一步（收尾）：

1. 已完成：新增 `./scripts/phase4_pressure_sample.sh`，补齐压测抽检入口，报告默认输出到 `data/reports/`。
2. 已完成：在 `.github/workflows/ci.yml` 中补齐三类证据产物上传（backend/frontend/smoke）。
3. 已完成：运行 `make acceptance`（2026-03-08 22:26 +08:00），形成包含策略接口与策略日志断言的最新本地通过基线。
4. 待执行：触发 CI 首次远端全流程并补充远端证据产物。
5. 待执行：按需开展 Phase 4 压测抽检并保留报告产物。

## 10. 变更记录（摘要）

### 2026-02-25

- 完成基础系统：认证、上游/节点管理、同步、固定输出、备份恢复、容器化部署。
- 完成增强能力：系统日志与同步日志、多 Token、自动备份、快照回滚。
- 完成稳定性修复：同步超时配置化、SQLite 同步阻塞修复、`414 URI Too Long` 修复、同步语义修正。
- 完成文档整理：`README` 去重并聚焦用途，新增 `docs/TROUBLESHOOTING.md` 与 `docs/BACKUP_RESTORE.md`。
- 完成安全增强：服务启动时对弱 `ADMIN_PASSWORD` / `JWT_SECRET` 输出告警（不阻断启动）。

### 2026-03-02

- 完成 O1：前端移除 `localStorage` token 依赖，改为 Cookie 会话优先。
- 完成 O2：登录接口新增 IP + 用户名双维度限流与连续失败锁定。
- 完成 O3：`/clash`、`/singbox` 增加 ETag/If-None-Match/304 协商与缓存头。
- 完成 O4：同步链路引入 worker pool 并发执行、指数退避重试、失败分类日志与隔离执行。
- 完成 O5：新增 `upstreams.enabled`、`manual_nodes.enabled`、`snapshots(kind,id)` 索引并验证查询计划命中（`auth_tokens.admin_id` 沿用原索引）。
- 完成 O6：将 `subconverter` 镜像固定为 digest（验证日期：2026-03-02），新增 `SUBLINK_IMAGE` 配置项。
- 完成 O7：新增 `/metrics` 端点、HTTP/同步链路指标、结构化 `system_logs.detail` 字段（`request_id/module/action/result/duration_ms/detail`）。
- 完成 O8：新增 `.github/workflows/ci.yml`，落地后端 `go test/go vet`、前端 `npm ci && npm run build`、Docker 冒烟检查。
- 新增 Phase 4 回归脚本：`scripts/phase4_acceptance.sh`，覆盖健康检查、鉴权、ETag/304、备份、登录限流锁定、同步重试与结构化日志字段验证。
- 执行 Phase 4 回归脚本并通过：修正系统日志断言为兼容转义 JSON 字段匹配（`request_id`/`sync_upstream_retry`），脚本在本地 Docker 环境全量通过。
- 更新配置示例与文档：新增认证 Cookie、登录防护、输出缓存协商、`SUBLINK_IMAGE` 与观测入口说明。
- 补齐 Phase 4 收尾资产：新增 `scripts/phase4_pressure_sample.sh`，并为 CI job 增加证据产物上传。
