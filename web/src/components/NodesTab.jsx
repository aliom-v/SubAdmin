export default function NodesTab({
  busy,
  nodeForm,
  onNodeFormChange,
  onCreateNode,
  nodes,
  onNodeFieldChange,
  onUpdateNode,
  onDeleteNode
}) {
  return (
    <section className="panel">
      <h2>手动节点管理</h2>
      <form className="grid-form" onSubmit={onCreateNode}>
        <input placeholder="名称" value={nodeForm.name} onChange={(e) => onNodeFormChange('name', e.target.value)} />
        <input placeholder="节点 URI" value={nodeForm.raw_uri} onChange={(e) => onNodeFormChange('raw_uri', e.target.value)} />
        <input placeholder="分组" value={nodeForm.group_name} onChange={(e) => onNodeFormChange('group_name', e.target.value)} />
        <label className="inline-check">
          <input type="checkbox" checked={nodeForm.enabled} onChange={(e) => onNodeFormChange('enabled', e.target.checked)} />
          启用
        </label>
        <button disabled={busy}>新增节点</button>
      </form>

      <div className="list-wrap">
        {nodes.map((item) => (
          <article className="list-row" key={item.id}>
            <input value={item.name} onChange={(e) => onNodeFieldChange(item.id, 'name', e.target.value)} />
            <input value={item.raw_uri} onChange={(e) => onNodeFieldChange(item.id, 'raw_uri', e.target.value)} />
            <input value={item.group_name} onChange={(e) => onNodeFieldChange(item.id, 'group_name', e.target.value)} />
            <label className="inline-check">
              <input
                type="checkbox"
                checked={item.enabled}
                onChange={(e) => onNodeFieldChange(item.id, 'enabled', e.target.checked)}
              />
              启用
            </label>
            <div className="row-actions">
              <button type="button" onClick={() => onUpdateNode(item)} disabled={busy}>
                保存
              </button>
              <button type="button" onClick={() => onDeleteNode(item.id)} disabled={busy} className="danger">
                删除
              </button>
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}
