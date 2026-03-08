# SubAdmin

SubAdmin 是一个面向 Clash / Sing-box 的自托管订阅管理面板。
它把多个上游订阅与手动节点统一管理，输出固定订阅地址，并提供同步日志、备份恢复与快照回滚能力。

## 核心能力

- 统一管理多个上游订阅与手动节点，并进行去重、汇总与输出
- 提供固定订阅地址：`/clash`、`/singbox`
- 已完成高级同步策略 V1 闭环：策略模式、来源优先级、冲突预览、后台配置入口、策略指标与接口级测试
- 支持登录保护、同步重试隔离、输出 ETag/304、自动备份与快照回滚
- 提供 `/healthz`、`/metrics`、系统日志与同步日志，便于观测与排障

## 快速开始

前置条件：

- 已安装 Docker 与 Docker Compose
- 本地环境文件请从 `.env.example` 复制生成 `.env`，`.env` 不纳入 Git 跟踪

```bash
git clone git@github.com:aliom-v/SubAdmin.git
cd SubAdmin
cp .env.example .env
# 首次部署必须修改以下两项
# ADMIN_PASSWORD=你的强密码
# JWT_SECRET=长度至少16位的随机字符串
make up
```

默认访问地址（共存模式）：

- 管理后台：`http://<server-ip>:18081`
- API 健康检查：`http://<server-ip>:18080/healthz`
- 监控指标：`http://<server-ip>:18080/metrics`
- 固定输出：`http://<server-ip>:18081/clash`、`http://<server-ip>:18081/singbox`

## 本地验证

快速验收：

```bash
curl -fsS http://127.0.0.1:18080/healthz
curl -fsS http://127.0.0.1:18080/metrics | head
make ps
```

统一命令入口：

```bash
make verify
make acceptance
make pressure
make logs SERVICE=api
```

说明：

- `make verify`：完整校验（需要 Go 1.22+、Node.js 20+ 与 npm）
- `make acceptance`：执行 Phase 4 回归脚本；会使用临时 Docker 数据卷，避免本地 `data/` 状态污染验收结果
- `make pressure`：执行 Phase 4 压测抽检，报告默认输出到 `data/reports/`
- `make logs SERVICE=api`：查看指定服务最近日志；不传 `SERVICE` 时默认查看 `api web sublink`

## 部署模式

- 共存模式（推荐）：`make up`
- 网关模式（走 80/443）：先在 `.env` 设置 `DOMAIN`，再执行 `make gateway-up`

网关模式访问：

- 管理后台：`https://<your-domain>/admin`
- Clash 输出：`https://<your-domain>/clash`
- Sing-box 输出：`https://<your-domain>/singbox`

## 关键配置

- `API_TIMEOUT_SECONDS`：API 请求总超时（默认 `300`）
- `SCHEDULER_JOB_TIMEOUT_SECONDS`：调度任务超时（默认 `300`）
- `HTTP_TIMEOUT_SECONDS`：单上游拉取超时（默认 `20`）
- `SUBLINK_SOURCE_BASE_URL`：`sublink` 拉取临时中转源地址（默认 `http://api:8080`）
- `SUBLINK_IMAGE`：`sublink` 容器镜像（默认固定为 `tindy2013/subconverter@sha256:6db842efdb44bc4c17c9ac05660ed35753e8c195ef105afcba55daceb1ab35bf`）
- `AUTH_COOKIE_SECURE` / `AUTH_COOKIE_SAMESITE`：认证 Cookie 安全属性（默认 `false` / `lax`）
- `LOGIN_RATE_MAX_IP` / `LOGIN_RATE_MAX_USERNAME`：登录固定窗口内尝试上限（默认 `30` / `10`）
- `LOGIN_LOCK_THRESHOLD` / `LOGIN_LOCK_SECONDS`：连续失败锁定阈值与时长（默认 `5` / `300` 秒）
- `OUTPUT_ETAG_ENABLED` / `OUTPUT_CACHE_CONTROL`：输出接口 ETag/304 与缓存控制（默认 `true` / `no-cache`）
- `SYNC_MAX_CONCURRENCY`：同步 worker 并发上限（默认 `3`）
- `SYNC_RETRY_MAX_ATTEMPTS`：单上游最大重试次数（默认 `3`，包含首轮）
- `SYNC_RETRY_BASE_DELAY_MS` / `SYNC_RETRY_MAX_DELAY_MS`：指数退避基准与上限（默认 `500` / `5000` 毫秒）

## 使用边界

- 上游输入应为 URI/base64 节点订阅，不是完整 `yaml/json` 配置文件
- 容器内访问主机服务不能用 `127.0.0.1/localhost`，应使用域名或 `host.docker.internal:<port>`
- 当前已具备高级同步策略 V1 闭环，但仍未覆盖更细粒度策略能力（按输出目标/按单节点规则等）

## 高级同步策略

- 管理后台已提供“高级同步策略”配置区，可设置策略模式、手动节点优先级、上游优先级并查看 preview 摘要
- API 已提供：`GET /api/strategy`、`PUT /api/strategy`、`POST /api/strategy/preview`
- 当前支持的策略模式：`merge_dedupe`、`priority_override`、`keep_both_rename`
- preview 基于当前缓存上游与启用手动节点计算，不会触发同步或写入输出
- 缓存模式下，保存策略后会自动刷新输出缓存；非缓存模式下可按需手动执行 `POST /api/sync`
- `/metrics` 已接入策略相关计数器：preview 次数、apply 次数、冲突组数量、丢弃节点数量

## 文档导航

- 状态摘要：`docs/STATUS.md`
- 最近优化摘要：`docs/RECENT_OPTIMIZATIONS.md`
- 遗留问题与优化清单：`docs/OPEN_ISSUES.md`
- 高级同步策略设计与实现状态：`docs/ADVANCED_SYNC_STRATEGY.md`
- 策略上线与回滚：`docs/STRATEGY_ROLLOUT.md`
- Phase 4 回归与验收记录：`docs/PHASE4_REGRESSION.md`
- 指标与监控说明：`docs/METRICS.md`
- 排障手册：`docs/TROUBLESHOOTING.md`
- 备份恢复：`docs/BACKUP_RESTORE.md`
- 前后端源码：`backend/`、`web/`

## License

MIT
