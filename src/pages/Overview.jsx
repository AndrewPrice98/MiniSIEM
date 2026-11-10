import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { BarList, TimelineChart } from '../components/charts.jsx'
import { Empty, ErrorState, Loading, SEVERITIES, Severity, formatTime, useAsync } from '../components/ui.jsx'

const POLL_MS = 15000

export default function Overview({ guest, demo }) {
  const poll = { pollMs: demo ? POLL_MS : 0 }
  const stats = useAsync(() => api.stats(), [], poll)
  const recent = useAsync(() => api.alerts({ sort: 'severity', order: 'desc', limit: 6 }), [], poll)
  const reloadAll = () => { stats.reload(); recent.reload() }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          {stats.data?.time_range?.start && (
            <span className="subtle mono">
              {formatTime(stats.data.time_range.start, { seconds: false })} → {formatTime(stats.data.time_range.end, { seconds: false })} UTC
            </span>
          )}
        </div>
      </div>

      {stats.loading && !stats.data && <Loading />}
      {stats.error && <ErrorState error={stats.error} onRetry={stats.reload} />}
      {stats.data && stats.data.total_events === 0 && (
        <div className="card" style={{ marginBottom: 10 }}>
          <Empty>
            {guest
              ? 'No events yet. The demo data is still loading; check back shortly.'
              : <>No events yet. Upload a log below, or run <code>python -m minisiem demo</code> in <code>backend/</code>.</>}
          </Empty>
        </div>
      )}

      {stats.data && stats.data.total_events > 0 && (
        <div className="stack">
          <div className="kpis">
            <div className="kpi">
              <div className="label">Events</div>
              <div className="value">{stats.data.total_events.toLocaleString()}</div>
              <div className="sub">
                {Object.entries(stats.data.events_by_source).map(([k, v]) => `${k} ${v}`).join(' · ')}
              </div>
            </div>
            <Link className="kpi" to="/alerts">
              <div className="label">Alerts</div>
              <div className="value">{stats.data.total_alerts}</div>
              <div className="sub">all severities</div>
            </Link>
            {SEVERITIES.map((s) => (
              <Link className={`kpi sev-${s}`} key={s} to={`/alerts?severity=${s}`}>
                <div className="label">{s}</div>
                <div className="value">{stats.data.alerts_by_severity[s]}</div>
                <div className="sub">alerts</div>
              </Link>
            ))}
          </div>

          <div className="card">
            <h2>Events over time <span className="muted">· per {stats.data.bucket}, UTC</span></h2>
            <TimelineChart timeline={stats.data.timeline} bucket={stats.data.bucket} />
          </div>

          <div className="grid grid-2">
            <div className="card">
              <h2>Top source IPs <span className="muted">· by alerts</span></h2>
              <BarList items={stats.data.top_source_ips} valueKey="alerts"
                to={(i) => `/alerts?source_ip=${encodeURIComponent(i.value)}`}
                extra={(i) => <Severity level={i.max_severity} />} />
            </div>
            <div className="card">
              <h2>Top targeted users <span className="muted">· by failed SSH logins</span></h2>
              <BarList items={stats.data.top_targeted_users} valueKey="failures"
                to={(i) => `/events?user_name=${encodeURIComponent(i.value)}&event_outcome=failure`} />
            </div>
          </div>

          <div className="card">
            <h2>Highest-severity alerts</h2>
            {recent.error && <ErrorState error={recent.error} onRetry={recent.reload} />}
            {recent.data && (
              <div className="table-wrap">
                <table>
                  <tbody>
                    {recent.data.items.map((a) => (
                      <tr key={a.id}>
                        <td><Severity level={a.severity} /></td>
                        <td><Link to={`/alerts/${a.id}`}>{a.summary}</Link></td>
                        <td className="ts">{formatTime(a.first_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="pager"><Link to="/alerts">All {recent.data.total} alerts →</Link></div>
              </div>
            )}
          </div>
        </div>
      )}

      {!guest && (
        <div className="card" style={{ marginTop: 10 }}>
          <h2>Upload a log file</h2>
          <UploadForm onDone={reloadAll} />
        </div>
      )}
    </>
  )
}

function UploadForm({ onDone }) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    const form = new FormData(e.currentTarget)
    if (!form.get('file')?.size) { setError(new Error('Choose a file first.')); return }
    setBusy(true); setError(null); setResult(null)
    try {
      setResult(await api.ingest(form))
      onDone()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit}>
      <div className="upload">
        <label className="field">Log file (.log or .txt)
          <input type="file" name="file" accept=".log,.txt,text/plain" />
        </label>
        <label className="field">Source type
          <select name="source_type" defaultValue="auth">
            <option value="auth">Linux auth log</option>
            <option value="web">Web access log</option>
          </select>
        </label>
        <label className="field">Host (optional)
          <input name="host" placeholder="e.g. web01" maxLength={255} />
        </label>
        <button className="primary" disabled={busy}>{busy ? 'Ingesting…' : 'Ingest & detect'}</button>
      </div>
      {error && <div className="result"><ErrorState error={error} /></div>}
      {result && (
        <div className="result">
          Parsed <strong>{result.ingest.parsed}</strong> of {result.ingest.lines} lines,
          stored <strong>{result.ingest.inserted}</strong> new events
          {result.ingest.duplicates > 0 && <> ({result.ingest.duplicates} already ingested)</>},
          raised <strong>{result.detection.new_alerts}</strong> new alerts.
          {result.ingest.unparsed > 0 && (
            <details style={{ marginTop: 6 }}>
              <summary>{result.ingest.unparsed} line(s) could not be parsed</summary>
              <pre className="raw">{result.ingest.unparsed_samples.join('\n')}</pre>
            </details>
          )}
        </div>
      )}
    </form>
  )
}
