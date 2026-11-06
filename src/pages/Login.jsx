import { useState } from 'react'
import { api } from '../api.js'

export default function Login({ onLogin, notice }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const { username: user } = await api.login(username.trim(), password)
      setPassword('')
      onLogin(user)
    } catch (err) {
      setError(err.status === 429 ? 'Too many failed attempts. Wait a few minutes and try again.' : err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <h2>Sign in</h2>
        <div className="brand login-brand">MINI<b>SIEM</b></div>
        {notice && <div className="state">{notice}</div>}
        <label className="field">Username
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)}
            maxLength={128} required autoFocus />
        </label>
        <label className="field">Password
          <input type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} maxLength={1024} required />
        </label>
        {error && <div className="state error" role="alert">{error}</div>}
        <button className="primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </div>
  )
}
