import { useEffect, useMemo, useState } from 'react'
import { apiRequest, getToken, login, logout } from './api'

const TABS = [
  { id: 'upstreams', label: '上游订阅' },
  { id: 'nodes', label: '手动节点' },
  { id: 'settings', label: '系统设置' },
  { id: 'backup', label: '备份恢复' },
  { id: 'logs', label: '系统日志' }
]

const emptyUpstream = {
  name: '',
  url: '',
  enabled: true,
  refresh_interval: 60
}

const emptyNode = {
  name: '',
  raw_uri: '',
  enabled: true,
  group_name: 'default'
}

function App() {
  const [booting, setBooting] = useState(true)
  const [authed, setAuthed] = useState(false)
  const [admin, setAdmin] = useState(null)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('upstreams')

  const [upstreams, setUpstreams] = useState([])
  const [nodes, setNodes] = useState([])
  const [settings, setSettings] = useState(null)
  const [syncLogs, setSyncLogs] = useState([])
  const [systemLogs, setSystemLogs] = useState([])
  const [tokens, setTokens] = useState([])
  const [newTokenValue, setNewTokenValue] = useState('')
  const [snapshots, setSnapshots] = useState([])
  const [snapshotKind, setSnapshotKind] = useState('')
  const [logLimit, setLogLimit] = useState(80)

  const [upstreamForm, setUpstreamForm] = useState(emptyUpstream)
  const [nodeForm, setNodeForm] = useState(emptyNode)
  const [rawUpstreamID, setRawUpstreamID] = useState(0)
  const [rawContent, setRawContent] = useState('')
  const [rawPreview, setRawPreview] = useState({ node_count: 0, preview_nodes: [], truncated: false })
  const [rawLastStatus, setRawLastStatus] = useState('')

  const [loginForm, setLoginForm] = useState({ username: 'admin', password: 'admin123' })
  const [passwordForm, setPasswordForm] = useState({ old_password: '', new_password: '' })
  const [tokenForm, setTokenForm] = useState({ name: '', hours: 720 })
  const [backupJSON, setBackupJSON] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const boot = async () => {
      if (!getToken()) {
        setBooting(false)
        return
      }
      try {
        await fetchMe()
        setAuthed(true)
      } catch {
        setAuthed(false)
      } finally {
        setBooting(false)
      }
    }
    boot()
  }, [])

  const statusSummary = useMemo(() => {
    return {
      upstreamEnabled: upstreams.filter((item) => item.enabled).length,
      nodeEnabled: nodes.filter((item) => item.enabled).length
    }
  }, [upstreams, nodes])

  async function fetchMe() {
    const me = await apiRequest('/api/me')
    setAdmin(me)
    return me
  }

  async function fetchAll() {
    const [upstreamData, nodeData, settingsData] = await Promise.all([
      apiRequest('/api/upstreams'),
      apiRequest('/api/nodes'),
      apiRequest('/api/settings')
    ])
    setUpstreams(upstreamData)
    setNodes(nodeData)
    setSettings(settingsData)
  }

  async function fetchLogs(limit = logLimit) {
    const normalizedLimit = Math.min(500, Math.max(10, Number(limit) || 80))
    const [syncData, systemData] = await Promise.all([
      apiRequest(`/api/logs/sync?limit=${normalizedLimit}`),
      apiRequest(`/api/logs/system?limit=${normalizedLimit}`)
    ])
    setSyncLogs(Array.isArray(syncData) ? syncData : [])
    setSystemLogs(Array.isArray(systemData) ? systemData : [])
  }

  async function fetchTokens() {
    const data = await apiRequest('/api/tokens')
    setTokens(Array.isArray(data) ? data : [])
  }

  async function fetchSnapshots(kind = snapshotKind) {
    const query = new URLSearchParams()
    query.set('limit', '100')
    if (kind) query.set('kind', kind)
    const data = await apiRequest(`/api/snapshots?${query.toString()}`)
    setSnapshots(Array.isArray(data) ? data : [])
  }

  async function handleLogin(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(loginForm.username, loginForm.password)
      await fetchMe()
      await fetchAll()
      setAuthed(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function handleLogout() {
    setBusy(true)
    try {
      await logout()
      setAuthed(false)
      setAdmin(null)
      setUpstreams([])
      setNodes([])
      setSettings(null)
      setSyncLogs([])
      setSystemLogs([])
      setTokens([])
      setNewTokenValue('')
      setSnapshots([])
      setRawUpstreamID(0)
      setRawContent('')
      setRawPreview({ node_count: 0, preview_nodes: [], truncated: false })
      setRawLastStatus('')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (!authed) return
    fetchAll().catch((err) => setError(err.message))
  }, [authed])

  useEffect(() => {
    if (!authed || activeTab !== 'logs') return
    fetchLogs().catch((err) => setError(err.message))
  }, [authed, activeTab])

  useEffect(() => {
    if (!authed || activeTab !== 'settings') return
    fetchTokens().catch((err) => setError(err.message))
  }, [authed, activeTab])

  useEffect(() => {
    if (!authed || activeTab !== 'backup') return
    fetchSnapshots().catch((err) => setError(err.message))
  }, [authed, activeTab, snapshotKind])

  useEffect(() => {
    if (upstreams.length === 0) {
      setRawUpstreamID(0)
      return
    }
    if (!upstreams.some((item) => item.id === rawUpstreamID)) {
      setRawUpstreamID(upstreams[0].id)
    }
  }, [upstreams, rawUpstreamID])

  async function createUpstream(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/upstreams', {
        method: 'POST',
        body: JSON.stringify(upstreamForm)
      })
      setUpstreamForm(emptyUpstream)
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function updateUpstream(item) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/upstreams/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify(item)
      })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function deleteUpstream(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/upstreams/${id}`, { method: 'DELETE' })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function syncUpstream(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/upstreams/${id}/sync`, { method: 'POST' })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function syncAll() {
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/sync', { method: 'POST' })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function loadRawContent(id = rawUpstreamID) {
    if (!id) {
      setError('请先选择上游')
      return
    }
    setBusy(true)
    setError('')
    try {
      const data = await apiRequest(`/api/upstreams/${id}/raw`)
      setRawContent(data.content || '')
      setRawLastStatus(data.last_status || '')
      const lines = (data.content || '')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
      setRawPreview({
        node_count: Number(data.node_count) || lines.length,
        preview_nodes: lines.slice(0, 30),
        truncated: lines.length > 30
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function previewRawContent() {
    if (!rawUpstreamID) {
      setError('请先选择上游')
      return
    }
    setBusy(true)
    setError('')
    try {
      const data = await apiRequest(`/api/upstreams/${rawUpstreamID}/raw/preview`, {
        method: 'POST',
        body: JSON.stringify({ content: rawContent })
      })
      setRawPreview({
        node_count: Number(data.node_count) || 0,
        preview_nodes: Array.isArray(data.preview_nodes) ? data.preview_nodes : [],
        truncated: Boolean(data.truncated)
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function saveRawContent() {
    if (!rawUpstreamID) {
      setError('请先选择上游')
      return
    }
    setBusy(true)
    setError('')
    try {
      const data = await apiRequest(`/api/upstreams/${rawUpstreamID}/raw`, {
        method: 'PUT',
        body: JSON.stringify({ content: rawContent })
      })
      setRawContent(data.content || rawContent)
      setRawLastStatus(data.last_status || '')
      const lines = (data.content || '')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
      setRawPreview({
        node_count: Number(data.node_count) || lines.length,
        preview_nodes: lines.slice(0, 30),
        truncated: lines.length > 30
      })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function createNode(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/nodes', {
        method: 'POST',
        body: JSON.stringify(nodeForm)
      })
      setNodeForm(emptyNode)
      setNodes(await apiRequest('/api/nodes'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function updateNode(item) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/nodes/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify(item)
      })
      setNodes(await apiRequest('/api/nodes'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function deleteNode(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/nodes/${id}`, { method: 'DELETE' })
      setNodes(await apiRequest('/api/nodes'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function saveSettings(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const payload = {
        cache_mode: settings.cache_mode,
        cache_interval: Number(settings.cache_interval),
        output_template: settings.output_template,
        auto_backup_enabled: settings.auto_backup_enabled,
        auto_backup_interval_hours: Number(settings.auto_backup_interval_hours),
        auto_backup_keep: Number(settings.auto_backup_keep)
      }
      const data = await apiRequest('/api/settings', {
        method: 'PUT',
        body: JSON.stringify(payload)
      })
      setSettings(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function changePassword(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/password', {
        method: 'PUT',
        body: JSON.stringify(passwordForm)
      })
      setPasswordForm({ old_password: '', new_password: '' })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function createToken(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const payload = {
        name: tokenForm.name,
        hours: Number(tokenForm.hours) || 720
      }
      const data = await apiRequest('/api/tokens', {
        method: 'POST',
        body: JSON.stringify(payload)
      })
      setNewTokenValue(data?.token || '')
      setTokenForm({ name: '', hours: 720 })
      await fetchTokens()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function revokeToken(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/tokens/${id}`, { method: 'DELETE' })
      await fetchTokens()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function exportBackup() {
    setBusy(true)
    setError('')
    try {
      const payload = await apiRequest('/api/backup/export')
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `subadmin-backup-${Date.now()}.json`
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function rollbackSnapshot(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/snapshots/${id}/rollback`, { method: 'POST' })
      await fetchSnapshots()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function exportSQLiteBackup() {
    setBusy(true)
    setError('')
    try {
      const blob = await fetch('/api/backup/sqlite', {
        method: 'GET',
        credentials: 'include',
        headers: {
          Authorization: `Bearer ${getToken()}`
        }
      }).then(async (response) => {
        if (!response.ok) {
          let message = 'request failed'
          try {
            const payload = await response.json()
            if (payload?.error) message = payload.error
          } catch {
            message = response.statusText || message
          }
          throw new Error(message)
        }
        return response.blob()
      })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `subadmin-sqlite-${Date.now()}.db`
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function importBackup(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const parsed = JSON.parse(backupJSON)
      await apiRequest('/api/backup/import', {
        method: 'POST',
        body: JSON.stringify(parsed)
      })
      await fetchAll()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function refreshLogs() {
    setBusy(true)
    setError('')
    try {
      await fetchLogs()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  function formatTime(value) {
    if (!value) return '-'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleString()
  }

  if (booting) {
    return <div className="center">初始化中...</div>
  }

  if (!authed) {
    return (
      <main className="auth-wrap">
        <section className="auth-card">
          <h1>SubAdmin</h1>
          <p>个人订阅管理中心</p>
          <form onSubmit={handleLogin}>
            <label>
              用户名
              <input
                value={loginForm.username}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, username: e.target.value }))}
                required
              />
            </label>
            <label>
              密码
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, password: e.target.value }))}
                required
              />
            </label>
            <button disabled={busy} type="submit">
              登录
            </button>
          </form>
          {error && <div className="error-box">{error}</div>}
        </section>
      </main>
    )
  }

  return (
    <main className="layout">
      <header className="topbar">
        <div>
          <h1>SubAdmin 控制台</h1>
          <p>
            管理员：{admin?.username || 'unknown'} | 已启用上游 {statusSummary.upstreamEnabled} 个，手动节点{' '}
            {statusSummary.nodeEnabled} 个
          </p>
        </div>
        <div className="actions">
          <button onClick={syncAll} disabled={busy}>
            全量同步
          </button>
          <button onClick={handleLogout} disabled={busy} className="ghost">
            退出
          </button>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={tab.id === activeTab ? 'active' : ''}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {error && <div className="error-box">{error}</div>}

      {activeTab === 'upstreams' && (
        <section className="panel">
          <h2>上游订阅管理</h2>
          <form className="grid-form" onSubmit={createUpstream}>
            <input
              placeholder="名称"
              value={upstreamForm.name}
              onChange={(e) => setUpstreamForm((prev) => ({ ...prev, name: e.target.value }))}
            />
            <input
              placeholder="订阅 URL"
              value={upstreamForm.url}
              onChange={(e) => setUpstreamForm((prev) => ({ ...prev, url: e.target.value }))}
            />
            <input
              type="number"
              min="1"
              placeholder="同步间隔(分钟)"
              value={upstreamForm.refresh_interval}
              onChange={(e) =>
                setUpstreamForm((prev) => ({ ...prev, refresh_interval: Number(e.target.value) || 60 }))
              }
            />
            <label className="inline-check">
              <input
                type="checkbox"
                checked={upstreamForm.enabled}
                onChange={(e) => setUpstreamForm((prev) => ({ ...prev, enabled: e.target.checked }))}
              />
              启用
            </label>
            <button disabled={busy}>新增上游</button>
          </form>

          <div className="list-wrap">
            {upstreams.map((item) => (
              <article className="list-row" key={item.id}>
                <input
                  value={item.name}
                  onChange={(e) =>
                    setUpstreams((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, name: e.target.value } : u))
                    )
                  }
                />
                <input
                  value={item.url}
                  onChange={(e) =>
                    setUpstreams((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, url: e.target.value } : u))
                    )
                  }
                />
                <input
                  type="number"
                  value={item.refresh_interval}
                  onChange={(e) =>
                    setUpstreams((prev) =>
                      prev.map((u) =>
                        u.id === item.id ? { ...u, refresh_interval: Number(e.target.value) || 60 } : u
                      )
                    )
                  }
                />
                <label className="inline-check">
                  <input
                    type="checkbox"
                    checked={item.enabled}
                    onChange={(e) =>
                      setUpstreams((prev) =>
                        prev.map((u) => (u.id === item.id ? { ...u, enabled: e.target.checked } : u))
                      )
                    }
                  />
                  启用
                </label>
                <small>{item.last_status || '未同步'}</small>
                <div className="row-actions">
                  <button onClick={() => syncUpstream(item.id)} disabled={busy}>
                    同步
                  </button>
                  <button onClick={() => updateUpstream(item)} disabled={busy}>
                    保存
                  </button>
                  <button onClick={() => deleteUpstream(item.id)} disabled={busy} className="danger">
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
                <select
                  value={rawUpstreamID || ''}
                  onChange={(e) => setRawUpstreamID(Number(e.target.value) || 0)}
                >
                  {upstreams.length === 0 && <option value="">暂无上游</option>}
                  {upstreams.map((item) => (
                    <option key={item.id} value={item.id}>
                      #{item.id} {item.name}
                    </option>
                  ))}
                </select>
              </label>
              <button onClick={() => loadRawContent()} disabled={busy || !rawUpstreamID} className="ghost">
                加载当前缓存
              </button>
              <button onClick={previewRawContent} disabled={busy || !rawUpstreamID}>
                预览解析
              </button>
              <button onClick={saveRawContent} disabled={busy || !rawUpstreamID}>
                保存为缓存
              </button>
            </div>
            <label>
              粘贴订阅原文（URI/base64）
              <textarea
                rows="10"
                value={rawContent}
                onChange={(e) => setRawContent(e.target.value)}
                placeholder="在这里粘贴整段订阅内容"
              />
            </label>
            <div className="raw-summary">
              <span>解析节点数：{rawPreview.node_count || 0}</span>
              <span>上游状态：{rawLastStatus || '未设置'}</span>
            </div>
            {rawPreview.preview_nodes.length > 0 && (
              <div className="raw-preview-wrap">
                <strong>预览（最多 30 条）</strong>
                <pre className="raw-preview">{rawPreview.preview_nodes.join('\n')}</pre>
                {rawPreview.truncated && <small className="muted">结果较长，仅显示前 30 条。</small>}
              </div>
            )}
          </div>
        </section>
      )}

      {activeTab === 'nodes' && (
        <section className="panel">
          <h2>手动节点管理</h2>
          <form className="grid-form" onSubmit={createNode}>
            <input
              placeholder="名称"
              value={nodeForm.name}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, name: e.target.value }))}
            />
            <input
              placeholder="节点 URI"
              value={nodeForm.raw_uri}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, raw_uri: e.target.value }))}
            />
            <input
              placeholder="分组"
              value={nodeForm.group_name}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, group_name: e.target.value }))}
            />
            <label className="inline-check">
              <input
                type="checkbox"
                checked={nodeForm.enabled}
                onChange={(e) => setNodeForm((prev) => ({ ...prev, enabled: e.target.checked }))}
              />
              启用
            </label>
            <button disabled={busy}>新增节点</button>
          </form>

          <div className="list-wrap">
            {nodes.map((item) => (
              <article className="list-row" key={item.id}>
                <input
                  value={item.name}
                  onChange={(e) =>
                    setNodes((prev) => prev.map((u) => (u.id === item.id ? { ...u, name: e.target.value } : u)))
                  }
                />
                <input
                  value={item.raw_uri}
                  onChange={(e) =>
                    setNodes((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, raw_uri: e.target.value } : u))
                    )
                  }
                />
                <input
                  value={item.group_name}
                  onChange={(e) =>
                    setNodes((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, group_name: e.target.value } : u))
                    )
                  }
                />
                <label className="inline-check">
                  <input
                    type="checkbox"
                    checked={item.enabled}
                    onChange={(e) =>
                      setNodes((prev) =>
                        prev.map((u) => (u.id === item.id ? { ...u, enabled: e.target.checked } : u))
                      )
                    }
                  />
                  启用
                </label>
                <div className="row-actions">
                  <button onClick={() => updateNode(item)} disabled={busy}>
                    保存
                  </button>
                  <button onClick={() => deleteNode(item.id)} disabled={busy} className="danger">
                    删除
                  </button>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'settings' && settings && (
        <section className="panel">
          <h2>系统设置</h2>
          <form className="settings" onSubmit={saveSettings}>
            <label className="inline-check">
              <input
                type="checkbox"
                checked={settings.cache_mode}
                onChange={(e) => setSettings((prev) => ({ ...prev, cache_mode: e.target.checked }))}
              />
              缓存模式（推荐）
            </label>
            <label>
              缓存刷新间隔（分钟）
              <input
                type="number"
                min="1"
                value={settings.cache_interval}
                onChange={(e) =>
                  setSettings((prev) => ({ ...prev, cache_interval: Number(e.target.value) || 10 }))
                }
              />
            </label>
            <label>
              输出模板
              <input
                value={settings.output_template}
                onChange={(e) => setSettings((prev) => ({ ...prev, output_template: e.target.value }))}
              />
            </label>
            <label className="inline-check">
              <input
                type="checkbox"
                checked={Boolean(settings.auto_backup_enabled)}
                onChange={(e) => setSettings((prev) => ({ ...prev, auto_backup_enabled: e.target.checked }))}
              />
              启用自动备份
            </label>
            <label>
              自动备份间隔（小时）
              <input
                type="number"
                min="1"
                value={settings.auto_backup_interval_hours ?? 24}
                onChange={(e) =>
                  setSettings((prev) => ({ ...prev, auto_backup_interval_hours: Number(e.target.value) || 24 }))
                }
              />
            </label>
            <label>
              备份保留份数
              <input
                type="number"
                min="1"
                value={settings.auto_backup_keep ?? 7}
                onChange={(e) =>
                  setSettings((prev) => ({ ...prev, auto_backup_keep: Number(e.target.value) || 7 }))
                }
              />
            </label>
            <button disabled={busy}>保存设置</button>
          </form>

          <h3>修改密码</h3>
          <form className="grid-form" onSubmit={changePassword}>
            <input
              type="password"
              placeholder="旧密码"
              value={passwordForm.old_password}
              onChange={(e) => setPasswordForm((prev) => ({ ...prev, old_password: e.target.value }))}
            />
            <input
              type="password"
              placeholder="新密码（至少6位）"
              value={passwordForm.new_password}
              onChange={(e) => setPasswordForm((prev) => ({ ...prev, new_password: e.target.value }))}
            />
            <button disabled={busy}>更新密码</button>
          </form>

          <h3>多 Token 访问控制</h3>
          <form className="grid-form" onSubmit={createToken}>
            <input
              placeholder="Token 名称（如：脚本机）"
              value={tokenForm.name}
              onChange={(e) => setTokenForm((prev) => ({ ...prev, name: e.target.value }))}
            />
            <input
              type="number"
              min="1"
              placeholder="有效期小时"
              value={tokenForm.hours}
              onChange={(e) => setTokenForm((prev) => ({ ...prev, hours: Number(e.target.value) || 720 }))}
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
                    onClick={() => revokeToken(item.id)}
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
      )}

      {activeTab === 'backup' && (
        <section className="panel">
          <h2>备份恢复</h2>
          <div className="row-actions">
            <button disabled={busy} onClick={exportBackup}>
              导出 JSON 备份
            </button>
            <button disabled={busy} onClick={exportSQLiteBackup} className="ghost">
              导出 SQLite
            </button>
          </div>
          <div className="snapshot-panel">
            <div className="snapshot-toolbar">
              <label className="inline-field">
                快照类型
                <select value={snapshotKind} onChange={(e) => setSnapshotKind(e.target.value)}>
                  <option value="">全部</option>
                  <option value="clash">clash</option>
                  <option value="singbox">singbox</option>
                </select>
              </label>
              <button disabled={busy} onClick={() => fetchSnapshots()} className="ghost">
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
                    <button onClick={() => rollbackSnapshot(item.id)} disabled={busy} className="danger">
                      回滚到此快照
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </div>
          <form onSubmit={importBackup}>
            <label>
              粘贴备份 JSON 后恢复
              <textarea
                rows="14"
                value={backupJSON}
                onChange={(e) => setBackupJSON(e.target.value)}
                placeholder={`{\n  "admins": [...], ...\n}`}
              />
            </label>
            <button disabled={busy}>导入恢复</button>
          </form>
        </section>
      )}

      {activeTab === 'logs' && (
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
                onChange={(e) => setLogLimit(Math.min(500, Math.max(10, Number(e.target.value) || 80)))}
              />
            </label>
            <button disabled={busy} onClick={refreshLogs}>
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
                      来源：{item.trigger_source || '-'} | 节点数：{item.node_count} | 耗时：
                      {item.duration_ms}ms | 时间：{formatTime(item.created_at)}
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
      )}
    </main>
  )
}

export default App
