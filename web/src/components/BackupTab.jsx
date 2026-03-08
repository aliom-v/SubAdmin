export default function BackupTab({
  busy,
  onExportBackup,
  onExportSQLiteBackup,
  snapshotKind,
  onSnapshotKindChange,
  onRefreshSnapshots,
  snapshots,
  onRollbackSnapshot,
  formatTime,
  backupJSON,
  onBackupJSONChange,
  onImportBackup
}) {
  return (
    <section className="panel">
      <h2>备份恢复</h2>
      <div className="row-actions">
        <button disabled={busy} onClick={onExportBackup}>
          导出 JSON 备份
        </button>
        <button disabled={busy} onClick={onExportSQLiteBackup} className="ghost">
          导出 SQLite
        </button>
      </div>
      <div className="snapshot-panel">
        <div className="snapshot-toolbar">
          <label className="inline-field">
            快照类型
            <select value={snapshotKind} onChange={(e) => onSnapshotKindChange(e.target.value)}>
              <option value="">全部</option>
              <option value="clash">clash</option>
              <option value="singbox">singbox</option>
            </select>
          </label>
          <button disabled={busy} onClick={onRefreshSnapshots} className="ghost">
            刷新快照
          </button>
        </div>
        <div className="snapshot-list">
          {snapshots.length === 0 && <p className="muted">暂无快照记录</p>}
          {snapshots.map((item) => (
            <article className="snapshot-row" key={item.id}>
              <div>
                <strong>
                  #{item.id} {item.kind}
                </strong>
                <div className="log-meta">
                  时间：{formatTime(item.created_at)} | 内容大小：{item.content_length || 0} 字节
                </div>
                {item.note && <div className="log-detail">{item.note}</div>}
              </div>
              <div className="row-actions">
                <button type="button" onClick={() => onRollbackSnapshot(item.id)} disabled={busy} className="danger">
                  回滚到此快照
                </button>
              </div>
            </article>
          ))}
        </div>
      </div>
      <form onSubmit={onImportBackup}>
        <label>
          粘贴备份 JSON 后恢复
          <textarea
            rows="14"
            value={backupJSON}
            onChange={(e) => onBackupJSONChange(e.target.value)}
            placeholder={`{\n  "admins": [...], ...\n}`}
          />
        </label>
        <button disabled={busy}>导入恢复</button>
      </form>
    </section>
  )
}
