import StrategyPanel from './StrategyPanel'

export default function SettingsTab({
  settings,
  busy,
  onSaveSettings,
  onSettingsFieldChange,
  strategy,
  strategyModes,
  activeStrategyMode,
  onSaveStrategy,
  onPreviewStrategy,
  onStrategyFieldChange,
  onStrategyPriorityChange,
  strategyPreview,
  strategyHasUnsavedChanges,
  strategyPreviewStale,
  strategySaveMessage,
  passwordForm,
  onPasswordFormChange,
  onChangePassword,
  tokenForm,
  onTokenFormChange,
  onCreateToken,
  newTokenValue,
  tokens,
  onRevokeToken,
  formatTime
}) {
  return (
    <section className="panel">
      <h2>系统设置</h2>
      <form className="settings" onSubmit={onSaveSettings}>
        <label className="inline-check">
          <input type="checkbox" checked={settings.cache_mode} onChange={(e) => onSettingsFieldChange('cache_mode', e.target.checked)} />
          缓存模式（推荐）
        </label>
        <label>
          缓存刷新间隔（分钟）
          <input
            type="number"
            min="1"
            value={settings.cache_interval}
            onChange={(e) => onSettingsFieldChange('cache_interval', Number(e.target.value) || 10)}
          />
        </label>
        <label>
          输出模板
          <input value={settings.output_template} onChange={(e) => onSettingsFieldChange('output_template', e.target.value)} />
        </label>
        <label className="inline-check">
          <input
            type="checkbox"
            checked={Boolean(settings.auto_backup_enabled)}
            onChange={(e) => onSettingsFieldChange('auto_backup_enabled', e.target.checked)}
          />
          启用自动备份
        </label>
        <label>
          自动备份间隔（小时）
          <input
            type="number"
            min="1"
            value={settings.auto_backup_interval_hours ?? 24}
            onChange={(e) => onSettingsFieldChange('auto_backup_interval_hours', Number(e.target.value) || 24)}
          />
        </label>
        <label>
          备份保留份数
          <input
            type="number"
            min="1"
            value={settings.auto_backup_keep ?? 7}
            onChange={(e) => onSettingsFieldChange('auto_backup_keep', Number(e.target.value) || 7)}
          />
        </label>
        <button disabled={busy}>保存设置</button>
      </form>

      <StrategyPanel
        busy={busy}
        strategy={strategy}
        strategyModes={strategyModes}
        activeStrategyMode={activeStrategyMode}
        onSaveStrategy={onSaveStrategy}
        onPreviewStrategy={onPreviewStrategy}
        onStrategyFieldChange={onStrategyFieldChange}
        onStrategyPriorityChange={onStrategyPriorityChange}
        strategyPreview={strategyPreview}
        strategyHasUnsavedChanges={strategyHasUnsavedChanges}
        strategyPreviewStale={strategyPreviewStale}
        strategySaveMessage={strategySaveMessage}
      />

      <h3>修改密码</h3>
      <form className="grid-form" onSubmit={onChangePassword}>
        <input
          type="password"
          placeholder="旧密码"
          value={passwordForm.old_password}
          onChange={(e) => onPasswordFormChange('old_password', e.target.value)}
        />
        <input
          type="password"
          placeholder="新密码（至少6位）"
          value={passwordForm.new_password}
          onChange={(e) => onPasswordFormChange('new_password', e.target.value)}
        />
        <button disabled={busy}>更新密码</button>
      </form>

      <h3>多 Token 访问控制</h3>
      <form className="grid-form" onSubmit={onCreateToken}>
        <input placeholder="Token 名称（如：脚本机）" value={tokenForm.name} onChange={(e) => onTokenFormChange('name', e.target.value)} />
        <input
          type="number"
          min="1"
          placeholder="有效期小时"
          value={tokenForm.hours}
          onChange={(e) => onTokenFormChange('hours', Number(e.target.value) || 720)}
        />
        <button disabled={busy}>创建 Token</button>
      </form>
      {newTokenValue && (
        <label>
          新 Token（仅本次展示）
          <textarea rows="3" value={newTokenValue} readOnly />
        </label>
      )}
      <div className="list-wrap">
        {tokens.length === 0 && <p className="muted">暂无 token</p>}
        {tokens.map((item) => (
          <article className="token-row" key={item.id}>
            <div>
              <strong>{item.name || `Token #${item.id}`}</strong>
              <div className="log-meta">
                到期：{formatTime(item.expires_at)} | 最近使用：{formatTime(item.last_used_at)} | 状态：
                {item.enabled ? '启用' : '已禁用'} {item.is_current ? '(当前会话)' : ''}
              </div>
            </div>
            <div className="row-actions">
              <button
                type="button"
                onClick={() => onRevokeToken(item.id)}
                disabled={busy || !item.enabled}
                className="danger"
              >
                吊销
              </button>
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}
