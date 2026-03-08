# SubAdmin Phase 4 回归与验收记录

更新时间：2026-03-08

## 1. 文档定位

- 本文档用于记录 Phase 4 回归脚本的覆盖范围、执行入口、已归档结果与证据留存方式。
- 它不替代 `docs/STATUS.md` 的总体状态说明，而是作为“验收证据台账”。
- 当脚本内容扩展、执行结果更新或压测抽检产生新报告时，应优先更新本文档。

## 2. 当前覆盖范围

当前 Phase 4 回归主入口：`scripts/phase4_acceptance.sh`

已覆盖的验证项：

1. `/healthz` 健康检查
2. `/metrics` 指标端点可读
3. 默认管理员登录与鉴权访问
4. 手动节点写入后的固定输出回归
5. 策略接口回归：
   - `GET /api/strategy`
   - `POST /api/strategy/preview`
   - `PUT /api/strategy`
6. `/clash` 的 ETag / 304 协商验证
7. `/singbox` 输出可访问性验证
8. `GET /api/backup/export` 备份导出验证
9. 登录限流 / 锁定验证
10. 上游失败重试与失败隔离日志验证
11. 系统日志 / 同步日志关键字段验证（含 `preview_strategy`、`update_strategy`）

压测抽检入口：`scripts/phase4_pressure_sample.sh`

压测默认关注端点：

- `/healthz`
- `/metrics`
- `/clash`
- `/singbox`

## 3. 推荐执行入口

### 3.1 回归验收

推荐入口：

```bash
make acceptance
```

等价脚本：

```bash
./scripts/phase4_acceptance.sh
```

说明：

- 脚本会自动拉起 `api`、`web`、`sublink` 相关容器。
- 默认使用 `http://127.0.0.1:18080` 作为 API 验证入口。
- 脚本退出码为 `0` 代表整体验收通过。
- 脚本会为 `api` 服务注入临时 Docker 数据卷，避免仓库内现有 `data/`、SQLite 与缓存状态污染验收结果。

### 3.2 压测抽检

推荐入口：

```bash
make pressure
```

等价脚本：

```bash
./scripts/phase4_pressure_sample.sh
```

常用参数：

```bash
TOTAL_REQUESTS=500 CONCURRENCY=50 START_STACK=false make pressure
```

输出目录默认位于：

- `data/reports/phase4-pressure-<timestamp>/summary.md`
- `data/reports/phase4-pressure-<timestamp>/*.raw.txt`
- `data/reports/phase4-pressure-<timestamp>/*.latency.txt`

### 3.3 CI 证据入口

当前 GitHub Actions 工作流已配置三类 artifact：

- `ci-evidence-backend`
- `ci-evidence-frontend`
- `ci-evidence-smoke`

建议关注内容：

- `ci-evidence-backend`：`go-test.log`、`go-vet.log`、`durations.env`
- `ci-evidence-frontend`：`npm-ci.log`、`npm-build.log`、`durations.env`
- `ci-evidence-smoke`：`docker-compose-up-attempt-*.log`、`healthz.json`、`login.json`、`metrics.txt`、`output-statuses.txt`、`smoke.meta`

当前状态：

- workflow 与 artifact 上传规则已经配置完成。
- 本文档尚待首次远端执行后回填具体运行时间、结果与 artifact 名称。

## 4. 已归档结果

### 4.1 已知通过记录

| 日期 | 环境 | 命令 | 结果 | 说明 |
|---|---|---|---|---|
| 2026-03-08 23:20 +08:00 | 当前本地 Docker 环境 | `make acceptance` | 通过 | 已形成包含策略接口、策略日志断言与临时数据卷隔离的最新本地通过基线 |
| 2026-03-02 14:18 +08:00 | 本地 Docker 环境 | `./scripts/phase4_acceptance.sh` | 通过 | 首轮 Phase 4 本地基线通过记录 |

说明：

- 上述记录是当前仓库内已明确留档的通过结果。
- 当前最新建议基线为 2026-03-08 23:20 +08:00 这次执行结果。

### 4.2 当前结论

- 扩展到策略接口与策略日志断言后的最新脚本，已在本地 Docker 环境重新执行并通过。
- 当前已具备新的本地通过基线；后续只需在 CI / 远端环境补充对应 artifact 与远端记录即可。
- 当前 CI artifact 的命名与日志落点已经固定，后续补证据时无需再重新设计归档结构。

## 5. 回填建议

每次执行回归后，建议至少回填以下信息：

1. 执行日期与时区
2. 执行环境（本地 Docker / CI / 测试机）
3. 执行命令
4. 结果（通过 / 失败 / 阻塞）
5. 失败阶段或阻塞原因
6. 证据位置（日志、报告、CI artifact）
7. 是否需要同步更新 `docs/STATUS.md`

推荐记录模板：

```md
| 2026-03-08 20:00 +08:00 | GitHub Actions | `make acceptance` | 通过 | artifact: ci-acceptance-20260308 |
```

## 6. 压测抽检结果建议

`phase4_pressure_sample.sh` 的 `summary.md` 建议至少关注：

- `success_rate`
- `avg_s`
- `p50_s`
- `p95_s`
- `p99_s`
- `max_s`

建议判定：

- `/healthz`、`/metrics` 应保持稳定 `200`
- `/clash`、`/singbox` 在不同模式下允许出现 `200` / `304` / `502`，需结合当时数据状态判断
- 若 `p95`、`p99` 明显恶化，应同时留存对应时间段的容器日志与系统日志

## 7. 最小证据清单

每次正式回归或压测后，建议至少保留：

- 执行时间
- Git 提交或分支信息
- 执行命令
- 退出码
- 关键日志或 CI artifact 名称
- 压测报告目录（如有）
- 是否已同步更新 `docs/STATUS.md`

## 8. 相关文档

- 总体状态：`docs/STATUS.md`
- 遗留问题：`docs/OPEN_ISSUES.md`
- 策略上线与回滚：`docs/STRATEGY_ROLLOUT.md`
- 指标与监控说明：`docs/METRICS.md`
