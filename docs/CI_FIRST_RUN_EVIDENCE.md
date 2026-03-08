# CI 首次远端执行留痕

更新时间：2026-03-02（新增留痕模板）

## 1. 目的

- 为 O7/O8 的“已落地”补齐首次远端执行证据。
- 记录构建耗时、重试行为、关键接口冒烟结果。
- 建立后续回归和告警阈值调整的基线材料。

## 2. 首次执行步骤

1. 触发一次 `.github/workflows/ci.yml`（建议通过 PR）。
2. 打开该次 workflow run，确认 `backend`、`frontend`、`smoke` 三个 job 均完成。
3. 下载三份证据产物：
   - `ci-evidence-backend`
   - `ci-evidence-frontend`
   - `ci-evidence-smoke`

如使用 GitHub CLI：

```bash
gh run list --workflow ci.yml --limit 5
gh run download <run-id> -n ci-evidence-backend -D data/reports/ci/<run-id>/backend
gh run download <run-id> -n ci-evidence-frontend -D data/reports/ci/<run-id>/frontend
gh run download <run-id> -n ci-evidence-smoke -D data/reports/ci/<run-id>/smoke
```

## 3. 证据清单（必填）

| 字段 | 内容 |
|---|---|
| Run URL | 待填 |
| Run ID | 待填 |
| Commit SHA | 待填 |
| 触发时间（UTC） | 待填 |
| 总耗时 | 待填 |
| 结果 | 待填（成功/失败） |

## 4. 关键数据回填

### 4.1 Backend

- `go test` 耗时（秒）：待填
- `go vet` 耗时（秒）：待填
- 失败信息（如有）：待填

### 4.2 Frontend

- `npm ci` 耗时（秒）：待填
- `npm run build` 耗时（秒）：待填
- 失败信息（如有）：待填

### 4.3 Smoke

- `docker compose up` 尝试次数：待填
- `healthz` 检查结果：待填
- `login` 检查结果：待填
- `metrics` 检查结果：待填
- `/clash` `/singbox` 状态分布：待填

## 5. 结论与后续动作

1. 是否满足当前门禁目标：待填。
2. 是否需要调整重试策略：待填。
3. 是否需要调整告警阈值：待填。
4. 责任人和完成日期：待填。
