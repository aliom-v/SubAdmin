# 最近优化摘要

更新时间：2026-03-08

## 1. 文档定位

- 本文档用于集中整理最近两轮已完成的高价值优化，避免信息分散在提交记录、状态文档和对话里。
- 它不替代 `docs/STATUS.md` 的总体状态说明，也不替代 `docs/OPEN_ISSUES.md` 的后续待办列表。
- 适合在回顾“最近完成了什么、为什么这样做、下一步该看哪里”时快速查阅。

## 2. 本轮已完成项

### 2.1 策略观测与接口级覆盖

已完成：

- 为高级同步策略补齐 `/metrics` 计数器：
  - `subadmin_strategy_preview_total`
  - `subadmin_strategy_apply_total`
  - `subadmin_strategy_conflicts_total`
  - `subadmin_strategy_dropped_nodes_total`
- 在策略 preview / apply 流程中补齐指标采集与摘要日志。
- 为 `/api/strategy` 增加后端 HTTP 层集成测试，覆盖：
  - 默认配置读取
  - 非法模式校验
  - preview / update 持久化与指标暴露
  - 缓存模式下保存策略后的输出刷新

涉及文件：

- `backend/internal/server/metrics.go`
- `backend/internal/server/strategy.go`
- `backend/internal/server/strategy_api_test.go`
- `docs/METRICS.md`
- `docs/ADVANCED_SYNC_STRATEGY.md`

当前价值：

- 策略功能从“可用”提升为“可观测、可回归、可持续验证”。
- 后续若继续扩展策略能力，可以先从现有指标和接口测试基线继续演进，而不必回到纯手工验证。

### 2.2 Phase 4 验收隔离与本地基线稳定化

已完成：

- `scripts/phase4_acceptance.sh` 已改为在本地验收时为 `api` 服务注入临时 Docker 数据卷。
- `make acceptance` 不再复用仓库内已有 `data/`、SQLite 或缓存文件，避免历史状态污染回归结果。
- 最新本地通过基线已更新为 2026-03-08 23:20 +08:00。

涉及文件：

- `scripts/phase4_acceptance.sh`
- `docs/PHASE4_REGRESSION.md`
- `README.md`

当前价值：

- 本地重复执行 acceptance 更稳定。
- “保持本地和远程干净”的目标更容易落实，因为验收不再依赖清理仓库内持久化数据目录。

### 2.3 前端控制台首轮组件化拆分

已完成：

- `web/src/App.jsx` 从“大一统视图文件”收口为“状态管理 + 数据拉取 + 动作编排”。
- 控制台视图已按职责拆分为独立组件：
  - `web/src/components/AuthView.jsx`
  - `web/src/components/AppHeader.jsx`
  - `web/src/components/TabNav.jsx`
  - `web/src/components/UpstreamsTab.jsx`
  - `web/src/components/NodesTab.jsx`
  - `web/src/components/SettingsTab.jsx`
  - `web/src/components/StrategyPanel.jsx`
  - `web/src/components/BackupTab.jsx`
  - `web/src/components/LogsTab.jsx`

当前职责边界：

- `App.jsx`：集中维护状态、拉取接口数据、封装行为动作、决定当前展示页。
- 各子组件：只承接对应面板的 UI 和 props，不重复持有核心业务状态。

当前价值：

- 后续继续打磨策略 UX、日志展示或备份交互时，改动面更集中。
- 前端主页面已经具备继续细化为 hooks / shared utils 的基础，但当前还不必过度抽象。

### 2.4 策略 UX 基础反馈补齐

已完成：

- 保存策略后增加成功提示，并根据缓存模式给出后续操作说明。
- preview 增加“与当前草稿一致 / 已过期”的状态提示。
- 离开系统设置页、刷新页面或退出登录前，未保存策略草稿会触发提醒。
- `priority_override` 模式增加丢弃低优先级冲突节点的风险提示。

涉及文件：

- `web/src/App.jsx`
- `web/src/components/SettingsTab.jsx`
- `web/src/components/StrategyPanel.jsx`
- `web/src/styles.css`

当前价值：

- 管理员在反复调参时能更快识别“当前是否已保存”“当前 preview 是否仍有效”。
- `priority_override` 模式的风险更加显性，误操作概率更低。

## 3. 已完成验证

本轮相关验证已完成：

- `make acceptance`
- Docker 内 `go test ./internal/server`
- `cd web && npm run build`

说明：

- 当前仓库内已经有一套可复用的本地回归基线。
- 若后续继续做远端验证补齐或更细粒度策略能力，建议优先复用这三类验证入口。

## 4. 当前仍建议继续优化的方向

优先建议：

1. 远端 / CI 证据补齐
   - 触发首次远端全流程
   - 留存 acceptance / smoke / build 证据产物
   - 将执行时间和证据位置回填到文档
2. 更细粒度策略能力
   - 按输出目标分别配置策略
   - 单上游独立规则
   - 单节点例外规则
3. 前端结构继续抽象（仅在继续增长时）
   - 按需抽离 strategy hooks / shared utils
   - 若策略页继续变复杂，再考虑更细的 diff / 对比视图

## 5. 相关文档导航

- 总体状态：`docs/STATUS.md`
- 遗留问题与后续建议：`docs/OPEN_ISSUES.md`
- 指标与监控：`docs/METRICS.md`
- 策略设计与实现状态：`docs/ADVANCED_SYNC_STRATEGY.md`
- 回归与验收记录：`docs/PHASE4_REGRESSION.md`
