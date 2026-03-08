import { useEffect, useMemo, useState } from 'react'
import { apiRequest, login, logout } from './api'
import AppHeader from './components/AppHeader'
import AuthView from './components/AuthView'
import BackupTab from './components/BackupTab'
import LogsTab from './components/LogsTab'
import NodesTab from './components/NodesTab'
import SettingsTab from './components/SettingsTab'
import TabNav from './components/TabNav'
import UpstreamsTab from './components/UpstreamsTab'

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

const STRATEGY_MODES = [
  {
    id: 'merge_dedupe',
    label: '合并去重',
    description: '内容完全相同的节点自动去重；同名但内容不同的节点保留并自动重命名。'
  },
  {
    id: 'priority_override',
    label: '优先级覆盖',
    description: '同名冲突时仅保留优先级更高的来源，适合追求稳定唯一输出。'
  },
  {
    id: 'keep_both_rename',
    label: '全部保留并重命名',
    description: '同名冲突时尽量全部保留，并为低优先级项自动追加后缀。'
  }
]

function defaultUpstreamPriority(index) {
  return (index + 1) * 10
}

function normalizeStrategy(data) {
  const normalizedUpstreams = Array.isArray(data?.upstreams)
    ? data.upstreams.map((item, index) => ({
        id: item.id,
        name: item.name || `upstream-${item.id}`,
        priority: Number(item.priority) || defaultUpstreamPriority(index)
      }))
    : []

  return {
    strategy_mode: data?.strategy_mode || 'merge_dedupe',
    manual_nodes_priority: Number(data?.manual_nodes_priority ?? 0),
    rename_suffix_format: data?.rename_suffix_format || '[{source}]',
    upstreams: normalizedUpstreams
  }
}

function buildStrategyPayload(strategy) {
  return {
    strategy_mode: strategy.strategy_mode,
    manual_nodes_priority: Number(strategy.manual_nodes_priority) || 0,
    rename_suffix_format: strategy.rename_suffix_format || '[{source}]',
    upstreams: strategy.upstreams.map((item, index) => ({
      id: item.id,
      priority: Number(item.priority) || defaultUpstreamPriority(index)
    }))
  }
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
  const [strategy, setStrategy] = useState(null)
  const [strategyPreview, setStrategyPreview] = useState(null)
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

  const statusSummary = useMemo(
    () => ({
      upstreamEnabled: upstreams.filter((item) => item.enabled).length,
      nodeEnabled: nodes.filter((item) => item.enabled).length
    }),
    [upstreams, nodes]
  )

  const activeStrategyMode =
    STRATEGY_MODES.find((item) => item.id === strategy?.strategy_mode) || STRATEGY_MODES[0]

  async function fetchMe() {
    const me = await apiRequest('/api/me')
    setAdmin(me)
    return me
  }

  async function fetchStrategy() {
    const data = await apiRequest('/api/strategy')
    const normalized = normalizeStrategy(data)
    setStrategy(normalized)
    return normalized
  }

  async function refreshUpstreamsAndStrategy() {
    const [upstreamData, strategyData] = await Promise.all([apiRequest('/api/upstreams'), apiRequest('/api/strategy')])
    setUpstreams(upstreamData)
    setStrategy(normalizeStrategy(strategyData))
  }

  async function fetchAll() {
    const [upstreamData, nodeData, settingsData, strategyData] = await Promise.all([
      apiRequest('/api/upstreams'),
      apiRequest('/api/nodes'),
      apiRequest('/api/settings'),
      apiRequest('/api/strategy')
    ])
    setUpstreams(upstreamData)
    setNodes(nodeData)
    setSettings(settingsData)
    setStrategy(normalizeStrategy(strategyData))
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
      setStrategy(null)
      setStrategyPreview(null)
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
    Promise.all([fetchTokens(), fetchStrategy()]).catch((err) => setError(err.message))
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

  function updateLoginFormField(key, value) {
    setLoginForm((prev) => ({ ...prev, [key]: value }))
  }

  function updateUpstreamFormField(key, value) {
    setUpstreamForm((prev) => ({ ...prev, [key]: value }))
  }

  function updateUpstreamField(id, key, value) {
    setUpstreams((prev) => prev.map((item) => (item.id === id ? { ...item, [key]: value } : item)))
  }

  function updateNodeFormField(key, value) {
    setNodeForm((prev) => ({ ...prev, [key]: value }))
  }

  function updateNodeField(id, key, value) {
    setNodes((prev) => prev.map((item) => (item.id === id ? { ...item, [key]: value } : item)))
  }

  function updateSettingsField(key, value) {
    setSettings((prev) => ({ ...prev, [key]: value }))
  }

  function updatePasswordFormField(key, value) {
    setPasswordForm((prev) => ({ ...prev, [key]: value }))
  }

  function updateTokenFormField(key, value) {
    setTokenForm((prev) => ({ ...prev, [key]: value }))
  }

  function updateLogLimit(value) {
    setLogLimit(Math.min(500, Math.max(10, Number(value) || 80)))
  }

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
      await refreshUpstreamsAndStrategy()
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
      await refreshUpstreamsAndStrategy()
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
      await refreshUpstreamsAndStrategy()
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
      await refreshUpstreamsAndStrategy()
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
      await refreshUpstreamsAndStrategy()
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

  async function saveStrategy(event) {
    event.preventDefault()
    if (!strategy) return
    setBusy(true)
    setError('')
    try {
      const data = await apiRequest('/api/strategy', {
        method: 'PUT',
        body: JSON.stringify(buildStrategyPayload(strategy))
      })
      setStrategy(normalizeStrategy(data))
      setStrategyPreview(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function previewStrategyConfig() {
    if (!strategy) return
    setBusy(true)
    setError('')
    try {
      const data = await apiRequest('/api/strategy/preview', {
        method: 'POST',
        body: JSON.stringify(buildStrategyPayload(strategy))
      })
      setStrategyPreview(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  function updateStrategyField(key, value) {
    setStrategy((prev) => (prev ? { ...prev, [key]: value } : prev))
    setStrategyPreview(null)
  }

  function updateStrategyPriority(id, value, index) {
    setStrategy((prev) => {
      if (!prev) return prev
      return {
        ...prev,
        upstreams: prev.upstreams.map((item, itemIndex) =>
          item.id === id
            ? {
                ...item,
                priority: Number(value) || item.priority || defaultUpstreamPriority(itemIndex ?? index)
              }
            : item
        )
      }
    })
    setStrategyPreview(null)
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
        credentials: 'include'
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

  function renderActiveTab() {
    switch (activeTab) {
      case 'upstreams':
        return (
          <UpstreamsTab
            busy={busy}
            upstreamForm={upstreamForm}
            onUpstreamFormChange={updateUpstreamFormField}
            onCreateUpstream={createUpstream}
            upstreams={upstreams}
            onUpstreamFieldChange={updateUpstreamField}
            onSyncUpstream={syncUpstream}
            onUpdateUpstream={updateUpstream}
            onDeleteUpstream={deleteUpstream}
            rawUpstreamID={rawUpstreamID}
            onRawUpstreamChange={setRawUpstreamID}
            onLoadRawContent={() => loadRawContent()}
            onPreviewRawContent={previewRawContent}
            onSaveRawContent={saveRawContent}
            rawContent={rawContent}
            onRawContentChange={setRawContent}
            rawPreview={rawPreview}
            rawLastStatus={rawLastStatus}
          />
        )
      case 'nodes':
        return (
          <NodesTab
            busy={busy}
            nodeForm={nodeForm}
            onNodeFormChange={updateNodeFormField}
            onCreateNode={createNode}
            nodes={nodes}
            onNodeFieldChange={updateNodeField}
            onUpdateNode={updateNode}
            onDeleteNode={deleteNode}
          />
        )
      case 'settings':
        return settings ? (
          <SettingsTab
            settings={settings}
            busy={busy}
            onSaveSettings={saveSettings}
            onSettingsFieldChange={updateSettingsField}
            strategy={strategy}
            strategyModes={STRATEGY_MODES}
            activeStrategyMode={activeStrategyMode}
            onSaveStrategy={saveStrategy}
            onPreviewStrategy={previewStrategyConfig}
            onStrategyFieldChange={updateStrategyField}
            onStrategyPriorityChange={updateStrategyPriority}
            strategyPreview={strategyPreview}
            passwordForm={passwordForm}
            onPasswordFormChange={updatePasswordFormField}
            onChangePassword={changePassword}
            tokenForm={tokenForm}
            onTokenFormChange={updateTokenFormField}
            onCreateToken={createToken}
            newTokenValue={newTokenValue}
            tokens={tokens}
            onRevokeToken={revokeToken}
            formatTime={formatTime}
          />
        ) : (
          <section className="panel">
            <h2>系统设置</h2>
            <p className="muted">设置加载中…</p>
          </section>
        )
      case 'backup':
        return (
          <BackupTab
            busy={busy}
            onExportBackup={exportBackup}
            onExportSQLiteBackup={exportSQLiteBackup}
            snapshotKind={snapshotKind}
            onSnapshotKindChange={setSnapshotKind}
            onRefreshSnapshots={() => fetchSnapshots()}
            snapshots={snapshots}
            onRollbackSnapshot={rollbackSnapshot}
            formatTime={formatTime}
            backupJSON={backupJSON}
            onBackupJSONChange={setBackupJSON}
            onImportBackup={importBackup}
          />
        )
      case 'logs':
        return (
          <LogsTab
            busy={busy}
            logLimit={logLimit}
            onLogLimitChange={updateLogLimit}
            onRefreshLogs={refreshLogs}
            syncLogs={syncLogs}
            systemLogs={systemLogs}
            formatTime={formatTime}
          />
        )
      default:
        return null
    }
  }

  if (booting) {
    return <div className="center">初始化中...</div>
  }

  if (!authed) {
    return (
      <AuthView
        loginForm={loginForm}
        onFieldChange={updateLoginFormField}
        onSubmit={handleLogin}
        busy={busy}
        error={error}
      />
    )
  }

  return (
    <main className="layout">
      <AppHeader admin={admin} statusSummary={statusSummary} busy={busy} onSyncAll={syncAll} onLogout={handleLogout} />
      <TabNav tabs={TABS} activeTab={activeTab} onChange={setActiveTab} />
      {error && <div className="error-box">{error}</div>}
      {renderActiveTab()}
    </main>
  )
}

export default App
