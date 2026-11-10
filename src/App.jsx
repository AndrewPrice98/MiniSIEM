import { useCallback, useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import { api } from './api.js'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import AlertDetail from './pages/AlertDetail.jsx'
import Events from './pages/Events.jsx'
import Attack from './pages/Attack.jsx'
import Login from './pages/Login.jsx'
import { Empty, ErrorState, Loading } from './components/ui.jsx'

const NAV = [
  ['/', 'Overview'],
  ['/alerts', 'Alerts'],
  ['/events', 'Search'],
  ['/attack', 'ATT&CK'],
]

function Shell({ user, version, demo, guest, authConfigured, onLogout, onAdminSignIn }) {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">MINI<b>SIEM</b></div>
        <nav className="nav" aria-label="Main">
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === '/'}>{label}</NavLink>
          ))}
        </nav>
        <div className="status">
          {guest ? (
            <>
              <span className="tag" title="Hosted demo: you are browsing example data. Uploads and detection runs are disabled.">
                Demo · read-only
              </span>
              <a href="https://github.com/AndrewPrice98/MiniSIEM#quick-start" target="_blank" rel="noreferrer">
                Run it locally for the full version
              </a>
              {/* Without an admin account on the server, login would only return 503. */}
              {authConfigured && <button className="link" onClick={onAdminSignIn}>admin sign in</button>}
            </>
          ) : (
            <>
              {demo && (
                <span className="tag" title="Hosted demo: data is loaded from the example logs, and uploads are temporary.">
                  demo
                </span>
              )}
              <span className="led up" aria-hidden="true" />
              v{version} · {user}
              <button className="link" onClick={onLogout}>sign out</button>
            </>
          )}
        </div>
      </header>
      <main className="main">
        <Routes>
          <Route path="/" element={<Overview guest={guest} demo={demo} />} />
          <Route path="/alerts" element={<Alerts demo={demo} />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/events" element={<Events />} />
          <Route path="/attack" element={<Attack />} />
          <Route path="*" element={<Empty>Page not found.</Empty>} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  // checking -> (anon | user) ; 'unconfigured' when the server has no admin set up
  const [state, setState] = useState({ phase: 'checking' })

  const check = useCallback(async () => {
    try {
      const health = await api.health()
      if (health.guest) {
        // Demo mode: visitors browse read-only without signing in. A valid admin
        // cookie still wins (me.guest is false); an expired one falls back to guest.
        const me = await api.me()
        return setState({ phase: 'user', user: me.username, guest: me.guest, version: health.version, demo: health.demo,
          authConfigured: health.auth_configured })
      }
      if (!health.auth_configured) return setState({ phase: 'unconfigured' })
      try {
        const me = await api.me()
        setState({ phase: 'user', user: me.username, guest: false, version: health.version, demo: health.demo,
          authConfigured: true })
      } catch (err) {
        if (err.status === 401) setState({ phase: 'anon', version: health.version, demo: health.demo })
        else throw err
      }
    } catch (error) {
      setState({ phase: 'error', error })
    }
  }, [])

  useEffect(() => { check() }, [check])

  // Any API call that comes back 401 (session expired) returns to the login screen.
  useEffect(() => {
    const expire = () => setState((s) => (s.phase === 'user'
      ? { phase: 'anon', version: s.version, demo: s.demo, notice: 'Your session has expired. Sign in again.' }
      : s))
    window.addEventListener('minisiem:unauthorized', expire)
    return () => window.removeEventListener('minisiem:unauthorized', expire)
  }, [])

  async function logout() {
    try { await api.logout() } catch { /* clearing local state is enough */ }
    // In demo mode this lands back on the guest view; otherwise on the login page.
    await check()
  }

  if (state.phase === 'checking') return <Loading label="Connecting…" />
  if (state.phase === 'error') {
    return <div className="login-wrap"><ErrorState error={state.error} onRetry={check} /></div>
  }
  if (state.phase === 'unconfigured') {
    return (
      <div className="login-wrap">
        <div className="state error" role="alert">
          No admin account is configured on the server. Run{' '}
          <code>python -m minisiem create-admin</code> (or set the MINISIEM_* environment variables
          on your host) and restart the API.
        </div>
      </div>
    )
  }
  if (state.phase === 'anon') {
    return <Login notice={state.notice} onLogin={(user) => setState((s) => ({ ...s, phase: 'user', user, guest: false, notice: undefined }))}
      onCancel={state.canCancel ? check : undefined} />
  }
  return (
    <BrowserRouter>
      <Shell user={state.user} version={state.version} demo={state.demo} guest={state.guest}
        authConfigured={state.authConfigured}
        onLogout={logout}
        onAdminSignIn={() => setState((s) => ({ ...s, phase: 'anon', canCancel: true }))} />
    </BrowserRouter>
  )
}

export default App
