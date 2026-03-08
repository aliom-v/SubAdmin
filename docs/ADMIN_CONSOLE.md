# 管理后台与策略交互指南

更新时间：2026-03-08

## 1. 文档定位

- 本文档用于说明 SubAdmin 管理后台的页面结构、前端职责拆分、策略配置区交互反馈和相关验证入口。
- 它不替代 `docs/STATUS.md` 的总体状态说明，也不替代 `docs/ADVANCED_SYNC_STRATEGY.md` 的策略设计规则。
- 适合在继续维护前端控制台、交接策略 UX 行为或排查“为什么界面这样提示”时查阅。

## 2. 页面结构概览

当前管理后台主要由以下视图组成：

1. 登录页
2. 顶部栏与标签页导航
3. 上游订阅管理
4. 手动节点管理
5. 系统设置
6. 高级同步策略配置区
7. 备份恢复
8. 系统日志与同步日志

当前组件拆分如下：

- `web/src/App.jsx`
- `web/src/components/AuthView.jsx`
- `web/src/components/AppHeader.jsx`
- `web/src/components/TabNav.jsx`
- `web/src/components/UpstreamsTab.jsx`
- `web/src/components/NodesTab.jsx`
- `web/src/components/SettingsTab.jsx`
- `web/src/components/StrategyPanel.jsx`
- `web/src/components/BackupTab.jsx`
- `web/src/components/LogsTab.jsx`

## 3. 前端职责边界

### 3.1 `App.jsx`

当前主要职责：

- 维护控制台全局状态
- 拉取后端接口数据
- 封装保存、预览、同步、导出等行为动作
- 维护策略草稿、策略 preview 与提示状态
- 控制当前激活标签页与离开确认逻辑

当前不负责：

- 各面板的大段静态 UI 拼装
- 独立面板内的重复布局细节

### 3.2 子组件职责

- `AuthView.jsx`：登录页
- `AppHeader.jsx`：顶部状态摘要与全量同步 / 退出按钮
- `TabNav.jsx`：标签页切换
- `UpstreamsTab.jsx`：上游列表、原始缓存预览 / 编辑
- `NodesTab.jsx`：手动节点列表与编辑
- `SettingsTab.jsx`：系统设置、策略面板、密码修改、Token 管理容器
- `StrategyPanel.jsx`：高级同步策略 UI 与交互反馈核心视图
- `BackupTab.jsx`：备份、恢复与快照回滚
- `LogsTab.jsx`：系统日志 / 同步日志展示

## 4. 策略配置区的交互反馈

### 4.1 保存成功提示

触发条件：

- 管理员执行 `PUT /api/strategy` 保存成功。

当前行为：

- 保存成功后立即显示轻量成功提示。
- 若系统为缓存模式，提示“输出缓存已自动刷新”。
- 若系统为非缓存模式，提示“如需立即更新输出可手动执行全量同步”。

说明：

- 成功提示用于补足“策略已落库但是否已体现在输出中”的反馈差异。
- 它不会替代错误提示；请求失败仍通过全局错误框展示。

### 4.2 preview 新鲜度提示

触发条件：

- 管理员执行 `POST /api/strategy/preview` 后，会记录本次 preview 对应的草稿指纹。

当前行为：

- 若当前策略草稿与最近一次 preview 对应的草稿一致，界面显示“当前预览与当前草稿一致”。
- 若 preview 后又修改了策略模式、手动节点优先级、重命名模板或上游优先级，界面显示“当前预览已过期”。

说明：

- 过期 preview 不会被静默当作最新结果继续使用。
- 管理员在保存前应重新执行一次 preview，确认当前草稿对应的摘要与冲突结果。

### 4.3 未保存变更提醒

判定条件：

- 当前策略草稿与最近一次成功保存的策略配置不同。

当前行为：

- 设置页会显示“当前草稿有未保存变更”提示。
- 若此时离开“系统设置”标签页，会触发确认提醒。
- 若此时刷新页面，会触发浏览器级 `beforeunload` 提醒。
- 若此时在“系统设置”标签页点击退出登录，也会触发确认提醒。

当前边界：

- 离开提醒只针对策略草稿，不针对其他设置项或非策略标签页表单。
- 退出登录时的确认仅在当前停留于“系统设置”标签页且存在未保存策略草稿时触发。

### 4.4 `priority_override` 风险提示

触发条件：

- 当前策略模式为 `priority_override`。

当前行为：

- 界面会持续提示：该模式会丢弃低优先级的冲突节点。
- 若当前存在有效 preview，则会结合 `dropped_nodes` 提示预计丢弃数量。
- 若当前尚未 preview 或 preview 已过期，则提示管理员先重新 preview 再决定是否保存。

适用场景：

- 适合“必须保持输出稳定且来源有明确优先级”的场景。
- 不适合对冲突丢弃结果零容忍、需要最大化保留来源差异的场景。

### 4.5 preview 失效与清空边界

当前区分两类情况：

1. 草稿变更但数据源未变
   - preview 保留在界面上，但会被标记为“已过期”。
   - 典型触发：修改策略模式、优先级或后缀模板。

2. 数据源本身已变
   - 旧 preview 会被直接清空，避免沿用过时结果。
   - 典型触发：手动节点新增 / 修改 / 删除，或上游原始缓存内容被改写。

说明：

- 该设计的目标是区分“旧 preview 还能参考但需要重算”和“旧 preview 已经没有参考价值”。

## 5. 关键状态字段

策略交互当前主要依赖以下状态：

- `strategy`：当前策略草稿
- `strategyPreview`：最近一次 preview 结果
- `strategySavedFingerprint`：最近一次成功保存对应的策略指纹
- `strategyPreviewFingerprint`：最近一次 preview 对应的策略指纹
- `strategySaveMessage`：最近一次成功保存后的提示文本

对应实现文件：

- `web/src/App.jsx`
- `web/src/components/SettingsTab.jsx`
- `web/src/components/StrategyPanel.jsx`

## 6. 样式与展示

策略配置区当前主要依赖以下样式区域：

- `web/src/styles.css` 中的 `.strategy-*` 相关样式
- `.status-stack`
- `.status-box.info`
- `.status-box.success`
- `.status-box.warning`
- `.error-box`

说明：

- 成功、信息、风险提示已使用统一的 `status-box` 体系。
- 若后续继续扩展提示类型，优先复用 `status-box`，避免重复造样式块。

## 7. 推荐验证入口

本地建议至少执行：

```bash
cd web && npm run build
make acceptance
```

若涉及策略后端行为，补充执行：

```bash
docker run --rm -v /home/aliom/project/subadmin:/work -w /work/backend golang:1.22-bookworm sh -lc '/usr/local/go/bin/go test ./internal/server'
```

CI 当前已配置的证据入口：

- `ci-evidence-backend`
- `ci-evidence-frontend`
- `ci-evidence-smoke`

说明：

- 后端 artifact 包含 `go-test.log`、`go-vet.log` 与 `durations.env`
- 前端 artifact 包含 `npm-ci.log`、`npm-build.log` 与 `durations.env`
- smoke artifact 包含 `healthz.json`、`login.json`、`metrics.txt`、`output-statuses.txt`、`smoke.meta` 等证据

## 8. 后续建议

当前最值得继续做的不是再补基础提示，而是：

1. 补齐首次远端 / CI 执行后的证据回填
2. 若策略能力继续增长，再按需抽离 strategy hooks / shared utils
3. 若需要更复杂的策略对比，再考虑差异视图或批量调参辅助能力

## 9. 相关文档

- 总体状态：`docs/STATUS.md`
- 最近优化摘要：`docs/RECENT_OPTIMIZATIONS.md`
- 遗留问题与后续建议：`docs/OPEN_ISSUES.md`
- 策略设计与实现状态：`docs/ADVANCED_SYNC_STRATEGY.md`
- 策略上线与回滚：`docs/STRATEGY_ROLLOUT.md`
- 回归与验收记录：`docs/PHASE4_REGRESSION.md`
