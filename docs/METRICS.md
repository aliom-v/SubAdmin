# SubAdmin 指标与监控说明

更新时间：2026-03-08

## 1. 文档定位

- 本文档用于说明当前 `/metrics` 暴露的 Prometheus 指标、标签含义、使用建议与现阶段限制。
- 它聚焦“已有指标如何解读”，不替代 `docs/TROUBLESHOOTING.md` 的排障步骤，也不替代 `docs/STATUS.md` 的整体状态结论。
- 当新增或调整指标时，应同步更新本文档。

## 2. 暴露方式

指标端点：

- `GET /metrics`

快速检查：

```bash
curl -fsS http://127.0.0.1:18080/metrics | head
```

说明：

- 指标格式为 Prometheus 文本格式。
- 指标由服务内存中的采样器实时累积，适合被 Prometheus 周期性抓取。
- 如果是网关模式，请使用实际网关入口地址。

## 3. 当前指标清单

### 3.1 HTTP 请求总数

指标名：`subadmin_http_requests_total`

类型：`counter`

标签：

- `method`：HTTP 方法，如 `GET`、`POST`
- `route`：路由模式，如 `/healthz`、`/api/login`、`/api/upstreams/{id}/sync`
- `status`：响应状态码，如 `200`、`401`、`502`

用途：

- 观察接口访问量
- 判断异常状态码是否升高
- 按路由查看热点与失败分布

### 3.2 HTTP 请求耗时

指标名：`subadmin_http_request_duration_seconds`

类型：`histogram`

标签：

- `method`
- `route`

桶边界（秒）：

- `0.005`
- `0.01`
- `0.025`
- `0.05`
- `0.1`
- `0.25`
- `0.5`
- `1`
- `2.5`
- `5`
- `10`
- `30`
- `60`

用途：

- 观察 API 延迟分布
- 计算 p95 / p99
- 识别慢接口或回归后的尾延迟上升

### 3.3 单上游同步次数

指标名：`subadmin_sync_upstream_runs_total`

类型：`counter`

标签：

- `trigger`：触发来源，如 `manual`、`scheduler`
- `status`：同步结果，如 `ok`、`fail`、`skipped`
- `error_class`：失败分类，如 `none`、`disabled`、`timeout`、`upstream_5xx`、`upstream_rate_limited`

用途：

- 观察同步成功率
- 判断失败主要来自哪一类错误
- 区分人工触发与调度触发的稳定性差异

### 3.4 单上游同步重试次数

指标名：`subadmin_sync_upstream_retries_total`

类型：`counter`

标签：

- `trigger`
- `error_class`

用途：

- 观察重试压力是否升高
- 判断失败是否偏向可恢复错误（如超时、429、5xx）

### 3.5 单上游同步耗时

指标名：`subadmin_sync_upstream_duration_seconds`

类型：`histogram`

标签：

- `trigger`
- `status`

桶边界（秒）：

- `0.05`
- `0.1`
- `0.25`
- `0.5`
- `1`
- `2.5`
- `5`
- `10`
- `20`
- `30`
- `60`
- `120`
- `300`

用途：

- 观察单上游同步慢点
- 识别超时前的延迟抖动
- 比较成功与失败同步的耗时差异

### 3.6 批量同步次数

指标名：`subadmin_sync_batch_runs_total`

类型：`counter`

标签：

- `trigger`
- `status`

用途：

- 观察 `POST /api/sync` 或调度批量同步整体成功率
- 判断调度周期是否频繁触发失败批次

### 3.7 批量同步耗时

指标名：`subadmin_sync_batch_duration_seconds`

类型：`histogram`

标签：

- `trigger`
- `status`

桶边界（秒）：

- `0.05`
- `0.1`
- `0.25`
- `0.5`
- `1`
- `2.5`
- `5`
- `10`
- `20`
- `30`
- `60`
- `120`
- `300`

用途：

- 观察一次批量同步整体耗时
- 辅助评估并发、重试和上游质量对总时长的影响

## 4. 使用示例

### 4.1 看某个路由的请求量

```bash
curl -fsS http://127.0.0.1:18080/metrics | grep '^subadmin_http_requests_total'
```

### 4.2 看同步重试是否升高

```bash
curl -fsS http://127.0.0.1:18080/metrics | grep '^subadmin_sync_upstream_retries_total'
```

### 4.3 看批量同步耗时桶

```bash
curl -fsS http://127.0.0.1:18080/metrics | grep '^subadmin_sync_batch_duration_seconds_bucket'
```

## 5. 读数建议

- `subadmin_http_requests_total` 的 `status=5xx` 上升，通常表示服务端错误或上游转换异常增多。
- `subadmin_sync_upstream_retries_total` 上升，通常表示超时、限流或上游不稳定开始增多。
- `subadmin_sync_upstream_runs_total{status="fail"}` 上升，应结合系统日志中的 `sync_upstream_retry`、`sync_upstream` 一起看。
- `subadmin_sync_batch_duration_seconds` 的尾延迟升高，通常意味着某些上游整体拖慢了批量同步。

## 6. 当前限制

- 当前还没有独立的策略指标。
- 因此，`preview_strategy`、`update_strategy`、冲突数、丢弃数仍主要依赖系统日志观测，而不是 `/metrics`。
- 后续若新增以下指标，应同步更新本文档：
  - `subadmin_strategy_preview_total`
  - `subadmin_strategy_apply_total`
  - `subadmin_strategy_conflicts_total`
  - `subadmin_strategy_dropped_nodes_total`

## 7. 与压测抽检的关系

- `scripts/phase4_pressure_sample.sh` 主要对 `/healthz`、`/metrics`、`/clash`、`/singbox` 做并发抽检。
- 压测报告中的成功率与耗时，可以与 `/metrics` 一起交叉验证。
- 如果压测报告出现异常，而 `/metrics` 中的同步失败与重试指标也同步升高，通常说明问题不是单纯前端入口抖动，而是同步链路或上游质量问题。

## 8. 相关文档

- 总体状态：`docs/STATUS.md`
- 回归与验收记录：`docs/PHASE4_REGRESSION.md`
- 排障手册：`docs/TROUBLESHOOTING.md`
- 策略上线与回滚：`docs/STRATEGY_ROLLOUT.md`
