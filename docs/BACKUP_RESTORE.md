# SubAdmin 备份与恢复

更新时间：2026-02-25

## 1. 备份能力概览

- JSON 导出：`GET /api/backup/export`
- SQLite 导出：`GET /api/backup/sqlite`
- JSON 导入：`POST /api/backup/import`
- 自动备份：按设置定时写入 `data/backups/`

说明：

- JSON 适合跨环境迁移与审阅。
- SQLite 适合“原样快照”场景，恢复速度通常更快。

## 2. 手动导出

前提：请求需要已登录 Token（`Authorization: Bearer <token>`）或有效登录 Cookie。

### 2.1 导出 JSON

```bash
curl -fSL \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/backup/export \
  -o backup.json
```

### 2.2 导出 SQLite

```bash
curl -fSL \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:18080/api/backup/sqlite \
  -o subadmin.db
```

## 3. JSON 导入（高风险操作）

接口：`POST /api/backup/import`

行为说明：

- 导入会先清空再重建核心表（`admins`、`auth_tokens`、`upstreams`、`manual_nodes`、`settings`、`snapshots`）。
- 属于全量覆盖，不是增量合并。

导入示例：

```bash
curl -fSL -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data-binary @backup.json \
  http://127.0.0.1:18080/api/backup/import
```

建议流程：

1. 先导出当前环境备份（JSON + SQLite）再导入。
2. 导入后立即验证登录、上游列表、输出订阅是否正常。
3. 若异常，优先用 SQLite 快照恢复。

## 4. 自动备份

自动备份由系统设置控制，输出目录为：

- `data/backups/backup-YYYYMMDD-HHMMSS.json`
- `data/backups/backup-YYYYMMDD-HHMMSS.db`

保留策略：

- 系统按 `auto_backup_keep` 保留最近 N 份 JSON 和 N 份 DB，其余自动清理。
- 默认保留数量：7

## 5. 恢复演练建议

建议定期在测试环境做一次完整演练：

1. 从生产导出 JSON 与 SQLite。
2. 在测试环境导入 JSON，确认核心功能可用。
3. 验证项：
   - `/healthz` 返回 `{"status":"ok"}`
   - 可以正常登录后台
   - 上游同步可执行
   - `/clash` 和 `/singbox` 可输出
4. 记录演练日期、版本号、耗时和问题清单。

## 6. 最低恢复后检查清单

- 能登录后台并查看上游/节点列表
- 同步日志与系统日志可读取
- 固定输出地址可被客户端拉取
- 自动备份设置仍符合预期（开关、间隔、保留数）
