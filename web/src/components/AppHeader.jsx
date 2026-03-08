export default function AppHeader({ admin, statusSummary, busy, onSyncAll, onLogout }) {
  return (
    <header className="topbar">
      <div>
        <h1>SubAdmin 控制台</h1>
        <p>
          管理员：{admin?.username || 'unknown'} | 已启用上游 {statusSummary.upstreamEnabled} 个，手动节点{' '}
          {statusSummary.nodeEnabled} 个
        </p>
      </div>
      <div className="actions">
        <button onClick={onSyncAll} disabled={busy}>
          全量同步
        </button>
        <button onClick={onLogout} disabled={busy} className="ghost">
          退出
        </button>
      </div>
    </header>
  )
}
