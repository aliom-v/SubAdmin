export default function LogsTab({ busy, logLimit, onLogLimitChange, onRefreshLogs, syncLogs, systemLogs, formatTime }) {
  return (
    <section className="panel">
      <h2>系统日志与同步任务明细</h2>
      <div className="row-actions log-toolbar">
        <label className="inline-field">
          展示条数
          <input
            type="number"
            min="10"
            max="500"
            value={logLimit}
            onChange={(e) => onLogLimitChange(e.target.value)}
          />
        </label>
        <button disabled={busy} onClick={onRefreshLogs}>
          刷新日志
        </button>
      </div>

      <div className="logs-grid">
        <article>
          <h3>同步任务明细</h3>
          <div className="log-list">
            {syncLogs.length === 0 && <p className="muted">暂无同步记录</p>}
            {syncLogs.map((item) => (
              <div className="log-card" key={`sync-${item.id}`}>
                <div className="log-head">
                  <strong>
                    #{item.upstream_id} {item.upstream_name || 'unknown'}
                  </strong>
                  <span className={`log-badge ${item.status}`}>{item.status}</span>
                </div>
                <div className="log-meta">
                  来源：{item.trigger_source || '-'} | 节点数：{item.node_count} | 耗时：{item.duration_ms}ms | 时间：
                  {formatTime(item.created_at)}
                </div>
                {item.detail && <div className="log-detail">{item.detail}</div>}
              </div>
            ))}
          </div>
        </article>

        <article>
          <h3>系统日志</h3>
          <div className="log-list">
            {systemLogs.length === 0 && <p className="muted">暂无系统日志</p>}
            {systemLogs.map((item) => (
              <div className="log-card" key={`system-${item.id}`}>
                <div className="log-head">
                  <strong>
                    [{item.category}] {item.action}
                  </strong>
                  <span className={`log-badge ${item.level}`}>{item.level}</span>
                </div>
                <div className="log-meta">时间：{formatTime(item.created_at)}</div>
                {item.detail && <div className="log-detail">{item.detail}</div>}
              </div>
            ))}
          </div>
        </article>
      </div>
    </section>
  )
}
