export default function UpstreamsTab({
  busy,
  upstreamForm,
  onUpstreamFormChange,
  onCreateUpstream,
  upstreams,
  onUpstreamFieldChange,
  onSyncUpstream,
  onUpdateUpstream,
  onDeleteUpstream,
  rawUpstreamID,
  onRawUpstreamChange,
  onLoadRawContent,
  onPreviewRawContent,
  onSaveRawContent,
  rawContent,
  onRawContentChange,
  rawPreview,
  rawLastStatus
}) {
  return (
    <section className="panel">
      <h2>上游订阅管理</h2>
      <form className="grid-form" onSubmit={onCreateUpstream}>
        <input placeholder="名称" value={upstreamForm.name} onChange={(e) => onUpstreamFormChange('name', e.target.value)} />
        <input placeholder="订阅 URL" value={upstreamForm.url} onChange={(e) => onUpstreamFormChange('url', e.target.value)} />
        <input
          type="number"
          min="1"
          placeholder="同步间隔(分钟)"
          value={upstreamForm.refresh_interval}
          onChange={(e) => onUpstreamFormChange('refresh_interval', Number(e.target.value) || 60)}
        />
        <label className="inline-check">
          <input
            type="checkbox"
            checked={upstreamForm.enabled}
            onChange={(e) => onUpstreamFormChange('enabled', e.target.checked)}
          />
          启用
        </label>
        <button disabled={busy}>新增上游</button>
      </form>

      <div className="list-wrap">
        {upstreams.map((item) => (
          <article className="list-row" key={item.id}>
            <input value={item.name} onChange={(e) => onUpstreamFieldChange(item.id, 'name', e.target.value)} />
            <input value={item.url} onChange={(e) => onUpstreamFieldChange(item.id, 'url', e.target.value)} />
            <input
              type="number"
              value={item.refresh_interval}
              onChange={(e) => onUpstreamFieldChange(item.id, 'refresh_interval', Number(e.target.value) || 60)}
            />
            <label className="inline-check">
              <input
                type="checkbox"
                checked={item.enabled}
                onChange={(e) => onUpstreamFieldChange(item.id, 'enabled', e.target.checked)}
              />
              启用
            </label>
            <small>{item.last_status || '未同步'}</small>
            <div className="row-actions">
              <button type="button" onClick={() => onSyncUpstream(item.id)} disabled={busy}>
                同步
              </button>
              <button type="button" onClick={() => onUpdateUpstream(item)} disabled={busy}>
                保存
              </button>
              <button type="button" onClick={() => onDeleteUpstream(item.id)} disabled={busy} className="danger">
                删除
              </button>
            </div>
          </article>
        ))}
      </div>

      <div className="raw-editor">
        <h3>原始订阅内容预览 / 粘贴编辑</h3>
        <p className="muted">支持整段 URI 列表或 base64 订阅文本。保存后会写入该上游缓存。</p>
        <div className="raw-toolbar">
          <label className="inline-field">
            目标上游
            <select value={rawUpstreamID || ''} onChange={(e) => onRawUpstreamChange(Number(e.target.value) || 0)}>
              {upstreams.length === 0 && <option value="">暂无上游</option>}
              {upstreams.map((item) => (
                <option key={item.id} value={item.id}>
                  #{item.id} {item.name}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={onLoadRawContent} disabled={busy || !rawUpstreamID} className="ghost">
            加载当前缓存
          </button>
          <button type="button" onClick={onPreviewRawContent} disabled={busy || !rawUpstreamID}>
            预览解析
          </button>
          <button type="button" onClick={onSaveRawContent} disabled={busy || !rawUpstreamID}>
            保存为缓存
          </button>
        </div>
        <label>
          粘贴订阅原文（URI/base64）
          <textarea
            rows="10"
            value={rawContent}
            onChange={(e) => onRawContentChange(e.target.value)}
            placeholder="在这里粘贴整段订阅内容"
          />
        </label>
        <div className="raw-summary">
          <span>解析节点数：{rawPreview.node_count || 0}</span>
          <span>上游状态：{rawLastStatus || '未设置'}</span>
        </div>
        {rawPreview.preview_nodes?.length > 0 && (
          <div className="raw-preview-wrap">
            <strong>预览（最多 30 条）</strong>
            <pre className="raw-preview">{rawPreview.preview_nodes.join('\n')}</pre>
            {rawPreview.truncated && <small className="muted">结果较长，仅显示前 30 条。</small>}
          </div>
        )}
      </div>
    </section>
  )
}
