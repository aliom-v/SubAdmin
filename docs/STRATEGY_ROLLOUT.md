# SubAdmin 策略上线与回滚手册

更新时间：2026-03-08

## 1. 文档定位

- 本文档用于指导“高级同步策略”相关配置的上线、验证与回滚。
- 它聚焦策略变更本身，不替代 `docs/BACKUP_RESTORE.md` 的通用备份恢复说明，也不替代 `docs/TROUBLESHOOTING.md` 的通用排障说明。
- 目标是让管理员在调整策略模式、手动节点优先级、上游优先级时，有一套可重复执行的低风险流程。

## 2. 适用范围

适用于以下变更：

- 修改 `strategy_mode`
- 调整 `manual_nodes_priority`
- 调整各上游 `priority`
- 调整 `rename_suffix_format`

当前支持的策略模式：

- `merge_dedupe`
- `priority_override`
- `keep_both_rename`

说明：

- `GET /api/strategy`：查看当前生效策略
- `PUT /api/strategy`：保存策略配置
- `POST /api/strategy/preview`：预览策略结果，不写入配置、不触发同步、不改写输出

## 3. 变更前检查

建议至少完成以下检查后再上线：

1. 确认后台可正常登录，且当前环境可调用管理 API。
2. 先导出一份当前备份：
   - `GET /api/backup/export`
   - `GET /api/backup/sqlite`
3. 记录当前是否启用缓存模式（`cache_mode`）。
4. 保存当前策略配置，作为快速回滚基线：

```bash
curl -fsS \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/strategy
```

5. 如本次调整涉及上游优先级，建议同时记录当前启用上游列表与最近同步状态。

推荐至少保存两份文件：

```bash
curl -fsS \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/strategy \
  -o strategy-before.json

curl -fsS \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/backup/export \
  -o backup-before-strategy-change.json
```

## 4. 推荐上线流程

### 4.1 先做 preview

不要直接保存未验证的策略，先做一次 preview：

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data-binary @strategy-next.json \
  http://127.0.0.1:18080/api/strategy/preview
```

重点关注返回中的：

- `summary.input_nodes`
- `summary.output_nodes`
- `summary.deduped_nodes`
- `summary.renamed_nodes`
- `summary.dropped_nodes`
- `summary.conflict_groups`
- `conflicts`

建议判定：

- 若 `dropped_nodes`、`conflict_groups` 明显高于预期，不要直接上线。
- 若 `priority_override` 下出现大批冲突丢弃，应先确认是否符合业务意图。
- 若 `keep_both_rename` 下重命名数量过高，应确认后缀格式是否满足客户端可读性。

### 4.2 保存策略

确认 preview 结果符合预期后，再执行保存：

```bash
curl -fsS -X PUT \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data-binary @strategy-next.json \
  http://127.0.0.1:18080/api/strategy
```

行为说明：

- 保存会写入 `settings` 中的策略相关配置。
- 若系统启用了 `cache_mode=true`，保存后会自动刷新输出缓存。
- 若系统未启用缓存模式，保存本身不会触发上游同步；后续请求 `/clash`、`/singbox` 时会按当前策略实时计算输出。

### 4.3 按需刷新上游数据

策略保存不等于重新同步上游。

如果你希望“用最新上游内容 + 新策略”一起验证，建议补一次同步：

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/sync
```

建议场景：

- 非缓存模式下，想确认最新上游数据与新策略组合后的实时输出
- 刚刚调整了上游优先级，且怀疑当前缓存的上游内容不是最新
- 上线窗口允许做一次完整同步验证

### 4.4 验证固定输出

上线后至少验证：

```bash
curl -fsS http://127.0.0.1:18080/clash | head
curl -fsS http://127.0.0.1:18080/singbox | head
```

如果是网关模式，请把地址替换为实际网关入口。

## 5. 上线后验证

建议按以下顺序核对：

1. 再次读取当前策略，确认保存值与预期一致：

```bash
curl -fsS \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/strategy
```

2. 再做一次 preview，确认当前配置的摘要与预期一致。
3. 拉取 `/clash`、`/singbox`，确认输出能正常访问、节点数量/命名无明显异常。
4. 检查系统日志中是否存在以下动作：
   - `action=preview_strategy`
   - `action=update_strategy`
5. 如需做完整回归，执行：

```bash
make acceptance
```

或：

```bash
./scripts/phase4_acceptance.sh
```

## 6. 回滚方案

### 6.1 快速回滚：重新写回旧策略

这是首选方案，适用于“策略配置本身有误，但数据本身无需恢复”的场景。

```bash
curl -fsS -X PUT \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data-binary @strategy-before.json \
  http://127.0.0.1:18080/api/strategy
```

说明：

- 该方式只回退策略配置。
- 若启用缓存模式，回写旧策略后会自动刷新输出缓存。
- 这是最快、影响面最小的回滚方式。

### 6.2 输出级回滚：使用快照回滚缓存内容

适用于“缓存输出已经生成，但希望把 `/clash` / `/singbox` 缓存内容回退到旧版本”的场景。

接口：`POST /api/snapshots/:id/rollback`

重要限制：

- 快照回滚只回滚 `clash` / `singbox` 的缓存内容。
- 它不会回滚 `settings` 中保存的策略配置。
- 因此，快照回滚不能替代策略配置回滚。

建议流程：

1. 先确认目标快照 ID 与 `kind`。
2. 对需要的快照执行回滚。
3. 立即重新读取 `/api/strategy`，避免误以为策略配置也已恢复。

### 6.3 全量回滚：导入备份

适用于“策略配置、上游、节点、设置、快照都希望一起恢复”的场景。

接口：`POST /api/backup/import`

导入会清空并恢复以下数据：

- `admins`
- `auth_tokens`
- `upstreams`
- `manual_nodes`
- `settings`
- `snapshots`

示例：

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data-binary @backup-before-strategy-change.json \
  http://127.0.0.1:18080/api/backup/import
```

风险提示：

- 这是高风险全量覆盖操作，不是增量恢复。
- 导入后需要重新验证登录、上游列表、固定输出与日志是否正常。
- 如需更完整背景，请配合阅读 `docs/BACKUP_RESTORE.md`。

## 7. 风险提示

- `priority_override` 可能丢弃冲突节点，适合“必须明确优先级”的场景，不适合对冲突结果零容忍的场景。
- `keep_both_rename` 不会丢弃冲突节点，但会增加节点重命名和展示复杂度。
- preview 只做计算和摘要展示，不会修改数据库、缓存输出或触发同步。
- 保存策略不会主动刷新上游数据；是否需要补同步，应结合当前缓存内容是否可信来判断。
- 缓存模式与非缓存模式的上线体验不同：
  - 缓存模式：保存后自动刷新缓存输出
  - 非缓存模式：输出在请求时按当前策略实时计算
- 快照回滚与备份导入不是同一层级：
  - 快照回滚：只处理输出缓存
  - 备份导入：恢复完整数据与设置

## 8. 最小检查清单

上线前：

- 已导出 `strategy-before.json`
- 已导出完整备份 JSON / SQLite
- 已确认当前 `cache_mode` 状态
- 已完成一次 preview，结果符合预期

上线后：

- `GET /api/strategy` 返回值正确
- `/clash`、`/singbox` 可正常访问
- 节点数量、命名、冲突处理符合预期
- 系统日志已出现 `preview_strategy` / `update_strategy`

回滚时：

- 已优先尝试“重新写回旧策略”
- 若使用快照回滚，已明确它不恢复策略配置
- 若使用备份导入，已准备好导入后的登录与输出验证
