export default function AuthView({ loginForm, onFieldChange, onSubmit, busy, error }) {
  return (
    <main className="auth-wrap">
      <section className="auth-card">
        <h1>SubAdmin</h1>
        <p>个人订阅管理中心</p>
        <form onSubmit={onSubmit}>
          <label>
            用户名
            <input value={loginForm.username} onChange={(e) => onFieldChange('username', e.target.value)} required />
          </label>
          <label>
            密码
            <input
              type="password"
              value={loginForm.password}
              onChange={(e) => onFieldChange('password', e.target.value)}
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
