export default function StrategyPanel({
  busy,
  strategy,
  strategyModes,
  activeStrategyMode,
  onSaveStrategy,
  onPreviewStrategy,
  onStrategyFieldChange,
  onStrategyPriorityChange,
  strategyPreview
}) {
  return (
    <div className="section-block strategy-panel">
      <div>
        <h3>高级同步策略</h3>
        <p className="strategy-note">
          对 `/clash` 与 `/singbox` 聚合输出生效。预览基于当前缓存上游和已启用手动节点，不会触发同步。
        </p>
      </div>

      {strategy ? (
        <form className="settings" onSubmit={onSaveStrategy}>
          <div className="strategy-grid">
            <label>
              策略模式
              <select value={strategy.strategy_mode} onChange={(e) => onStrategyFieldChange('strategy_mode', e.target.value)}>
                {strategyModes.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              手动节点优先级
              <input
                type="number"
                value={strategy.manual_nodes_priority}
                onChange={(e) => onStrategyFieldChange('manual_nodes_priority', Number(e.target.value) || 0)}
              />
            </label>
            <label>
              重命名后缀模板
              <input
                value={strategy.rename_suffix_format}
                placeholder="[{source}]"
                onChange={(e) => onStrategyFieldChange('rename_suffix_format', e.target.value)}
              />
            </label>
          </div>

          <div className="log-meta">{activeStrategyMode.description}</div>

          <div className="strategy-priority-list">
            <strong>上游优先级</strong>
            {strategy.upstreams.length === 0 && <p className="muted">暂无上游，当前仅手动节点参与聚合。</p>}
            {strategy.upstreams.map((item, index) => (
              <div className="strategy-priority-row" key={item.id}>
                <div>
                  <strong>{item.name}</strong>
                  <div className="log-meta">ID: {item.id} · 数值越小优先级越高</div>
                </div>
                <input type="number" value={item.priority} onChange={(e) => onStrategyPriorityChange(item.id, e.target.value, index)} />
              </div>
            ))}
          </div>

          <div className="row-actions">
            <button disabled={busy}>保存策略</button>
            <button type="button" className="ghost" disabled={busy} onClick={onPreviewStrategy}>
              预览结果
            </button>
          </div>
        </form>
      ) : (
        <p className="muted">策略配置加载中…</p>
      )}

      {strategyPreview && (
        <div className="strategy-preview-block">
          <div className="strategy-summary">
            <div className="strategy-metric">
              <span>来源数</span>
              <strong>{strategyPreview.summary?.source_count ?? 0}</strong>
            </div>
            <div className="strategy-metric">
              <span>输入节点</span>
              <strong>{strategyPreview.summary?.input_nodes ?? 0}</strong>
            </div>
            <div className="strategy-metric">
              <span>输出节点</span>
              <strong>{strategyPreview.summary?.output_nodes ?? 0}</strong>
            </div>
            <div className="strategy-metric">
              <span>去重数量</span>
              <strong>{strategyPreview.summary?.deduped_nodes ?? 0}</strong>
            </div>
            <div className="strategy-metric">
              <span>重命名数量</span>
              <strong>{strategyPreview.summary?.renamed_nodes ?? 0}</strong>
            </div>
            <div className="strategy-metric">
              <span>丢弃数量</span>
              <strong>{strategyPreview.summary?.dropped_nodes ?? 0}</strong>
            </div>
          </div>

          <div className="strategy-columns">
            <article className="log-card">
              <h4>冲突处理</h4>
              {strategyPreview.conflicts?.length > 0 ? (
                <div className="log-list">
                  {strategyPreview.conflicts.map((item, index) => (
                    <div className="log-card" key={`${item.name}-${index}`}>
                      <strong>{item.name}</strong>
                      <div className="log-meta">处理方式：{item.resolution}</div>
                      {item.winner_source && <div className="log-meta">胜出来源：{item.winner_source}</div>}
                      {item.dropped_sources?.length > 0 && (
                        <div className="log-detail">丢弃来源：{item.dropped_sources.join('、')}</div>
                      )}
                      {item.renamed_sources?.length > 0 && (
                        <div className="log-detail">重命名来源：{item.renamed_sources.join('、')}</div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted">当前预览没有命名冲突。</p>
              )}
            </article>

            <article className="log-card">
              <h4>输出预览</h4>
              {strategyPreview.preview_nodes?.length > 0 ? (
                <ol className="strategy-list">
                  {strategyPreview.preview_nodes.map((item, index) => (
                    <li key={`${item}-${index}`}>{item}</li>
                  ))}
                </ol>
              ) : (
                <p className="muted">暂无可输出节点。</p>
              )}
            </article>
          </div>
        </div>
      )}
    </div>
  )
}
