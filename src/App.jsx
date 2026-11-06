import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import AlertDetail from './pages/AlertDetail.jsx'
import Events from './pages/Events.jsx'
import Attack from './pages/Attack.jsx'
import { Empty } from './components/ui.jsx'

const NAV = [
  ['/', 'Overview'],
  ['/alerts', 'Alerts'],
  ['/events', 'Event search'],
  ['/attack', 'ATT&CK coverage'],
]

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <aside className="sidebar">
          <div className="brand"><span className="brand-mark" aria-hidden="true" />MiniSIEM</div>
          <nav className="nav" aria-label="Main">
            {NAV.map(([to, label]) => (
              <NavLink key={to} to={to} end={to === '/'}>{label}</NavLink>
            ))}
          </nav>
        </aside>
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
