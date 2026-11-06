import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import { api } from './api.js'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import AlertDetail from './pages/AlertDetail.jsx'
import Events from './pages/Events.jsx'
import Attack from './pages/Attack.jsx'
import { Empty, useAsync } from './components/ui.jsx'

const NAV = [
  ['/', 'Overview'],
  ['/alerts', 'Alerts'],
  ['/events', 'Search'],
  ['/attack', 'ATT&CK'],
]

function ApiStatus() {
  const { data, error, loading } = useAsync(() => api.health(), [])
  const state = loading ? '' : error ? 'down' : 'up'
  return (
    <div className="status" title={error ? error.message : undefined}>
      <span className={`led ${state}`} aria-hidden="true" />
      {loading ? 'api …' : error ? 'api offline' : `api ok · v${data.version}`}
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <header className="topbar">
          <div className="brand">MINI<b>SIEM</b></div>
          <nav className="nav" aria-label="Main">
            {NAV.map(([to, label]) => (
              <NavLink key={to} to={to} end={to === '/'}>{label}</NavLink>
            ))}
          </nav>
          <ApiStatus />
        </header>
        <main className="main">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/events" element={<Events />} />
            <Route path="/attack" element={<Attack />} />
            <Route path="*" element={<Empty>Page not found.</Empty>} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
