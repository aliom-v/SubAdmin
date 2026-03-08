# Phase 4 压测抽检与复盘

更新时间：2026-03-02（新增压测抽检脚本）

## 1. 目的

- 为 Phase 4 收尾提供可重复的压测抽检入口。
- 固化性能基线（成功率、耗时分位、异常分布）。
- 形成首轮复盘输入，支撑下一轮优化优先级。

## 2. 执行方式

推荐命令（自动拉起 compose 栈并生成报告）：

```bash
REPORT_DIR="data/reports/phase4-pressure-$(date -u +%Y%m%d-%H%M%S)" \
TOTAL_REQUESTS=200 \
CONCURRENCY=20 \
./scripts/phase4_pressure_sample.sh
```

若已有运行中的环境，避免脚本自动启停容器：

```bash
START_STACK=false \
API_BASE="http://127.0.0.1:18080" \
REPORT_DIR="data/reports/phase4-pressure-$(date -u +%Y%m%d-%H%M%S)" \
./scripts/phase4_pressure_sample.sh
```

输出物：

- Markdown 摘要：`<REPORT_DIR>/summary.md`
- 原始结果：`<REPORT_DIR>/*.raw.txt`
- 耗时分布：`<REPORT_DIR>/*.latency.txt`

## 3. 抽检记录

| 日期（UTC） | 环境 | TOTAL_REQUESTS | CONCURRENCY | 结果路径 | 执行人 |
|---|---|---|---|---|---|
| 待填 | 待填 | 待填 | 待填 | 待填 | 待填 |

## 4. 结果摘要模板

### 4.1 核心观察

- `healthz` 成功率：待填
- `metrics` 成功率：待填
- `clash/singbox` 可接受返回（200/304/502）占比：待填
- P95 延迟（秒）：待填

### 4.2 主要问题

1. 待填
2. 待填

### 4.3 结论与行动项

1. 待填
2. 待填

## 5. 建议告警阈值（首版）

- `healthz` 非 200 比例 > 1%（5 分钟窗口）告警。
- `metrics` 非 200 比例 > 1%（5 分钟窗口）告警。
- `/clash`、`/singbox` 可接受状态（200/304/502）占比 < 99%（5 分钟窗口）告警。
- API P95 延迟持续高于 1.5s（连续 3 个窗口）告警。

阈值应以首次真实压测结果回填并校正。
