import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { BarList, TimelineChart } from '../components/charts.jsx'
import { Empty, ErrorState, Loading, SEVERITIES, Severity, formatTime, useAsync } from '../components/ui.jsx'

export default function Overview() {
  const stats = useAsync(() => api.stats(), [])
  const recent = useAsync(() => api.alerts({ sort: 'severity', order: 'desc', limit: 6 }), [])
  const reloadAll = () => { stats.reload(); recent.reload() }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          {stats.data?.time_range?.start && (
            <div className="subtle">
              Data from {formatTime(stats.data.time_range.start, { seconds: false })} to{' '}
              {formatTime(stats.data.time_range.end, { seconds: false })}
            </div>
          )}
        </div>
      </div>

      {stats.loading && !stats.data && <Loading />}
      {stats.error && <ErrorState error={stats.error} onRetry={stats.reload} />}
      {stats.data && stats.data.total_events === 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <Empty>
            No events yet. Upload a log below, or run <code>python -m minisiem demo</code> in <code>backend/</code>.
          </Empty>
        </div>
      )}

      {stats.data && stats.data.total_events > 0 && (
        <div className="stack">
          <div className="grid grid-tiles">
            <div className="card tile">
              <div className="label">Events</div>
              <div className="value">{stats.data.total_events.toLocaleString()}</div>
              <div className="muted" style={{ fontSize: '0.8rem' }}>
                {Object.entries(stats.data.events_by_source).map(([k, v]) => `${k}: ${v}`).join(' · ')}
              </div>
            </div>
            {SEVERITIES.map((s) => (
              <div className="card tile" key={s}>
                <Link to={`/alerts?severity=${s}`}>
                  <div className="label"><Severity level={s} /></div>
                  <div className="value">{stats.data.alerts_by_severity[s]}</div>
                  <div className="muted" style={{ fontSize: '0.8rem' }}>alerts</div>
                </Link>
              </div>
            ))}
          </div>

          <div className="card">
            <h2>Events over time <span className="muted" style={{ fontWeight: 400 }}>(per {stats.data.bucket}, UTC)</span></h2>
            <TimelineChart timeline={stats.data.timeline} bucket={stats.data.bucket} />
          </div>

          <div className="grid grid-2">
            <div className="card">
              <h2>Top source IPs <span className="muted" style={{ fontWeight: 400 }}>by alerts</span></h2>
              <BarList items={stats.data.top_source_ips} valueKey="alerts"
                to={(i) => `/alerts?source_ip=${encodeURIComponent(i.value)}`}
                extra={(i) => <Severity level={i.max_severity} />} />
            </div>
            <div className="card">
              <h2>Top targeted users <span className="muted" style={{ fontWeight: 400 }}>by failed SSH logins</span></h2>
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
                        <td className="nowrap muted">{formatTime(a.first_seen)}</td>
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

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Upload a log file</h2>
        <UploadForm onDone={reloadAll} />
      </div>
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
        <label className="field">Log file (.log, .txt, max 10 MB)
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
