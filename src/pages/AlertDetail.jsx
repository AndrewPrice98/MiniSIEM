import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { ErrorState, Loading, Severity, attackUrl, formatTime, useAsync } from '../components/ui.jsx'

const fmtSecs = (s) => (s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`)

const EVENT_COLUMNS = ['timestamp', 'event_action', 'event_outcome', 'user_name', 'source_ip']

export default function AlertDetail() {
  const { id } = useParams()
  const { data: a, loading, error, reload } = useAsync(() => api.alert(id), [id])

  if (loading && !a) return <Loading />
  if (error) {
    return (
      <>
        <p><Link to="/alerts">← Alerts</Link></p>
        <ErrorState error={error} onRetry={reload} />
      </>
    )
  }

  const rule = a.rule
  const technique = attackUrl(a.attack_technique)
  const search = (k, v) => `/events?${new URLSearchParams({ [k]: v })}`

  return (
    <>
      <p style={{ margin: '0 0 12px' }}><Link to="/alerts">← Alerts</Link></p>
      <div className="page-head">
        <div>
          <div style={{ marginBottom: 6 }}><Severity level={a.severity} /> <span className="muted">· Alert #{a.id}</span></div>
          <h1>{a.summary}</h1>
          <div className="subtle">{a.rule_title}</div>
        </div>
      </div>

      <div className="grid grid-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h2>Details</h2>
          <dl className="kv">
            <dt>Status</dt><dd>{a.status}</dd>
            <dt>First seen</dt><dd>{formatTime(a.first_seen)}</dd>
            <dt>Last seen</dt><dd>{formatTime(a.last_seen)}</dd>
            <dt>Events</dt><dd className="num">{a.event_count}</dd>
            <dt>Host</dt><dd>{a.host ? <Link to={search('host', a.host)}>{a.host}</Link> : '—'}</dd>
            <dt>Source IP</dt>
            <dd className="mono">
              {a.source_ip ? <>
                <Link to={search('source_ip', a.source_ip)}>{a.source_ip}</Link>{' '}
                <Link to={`/alerts?source_ip=${encodeURIComponent(a.source_ip)}`} className="muted">(other alerts)</Link>
              </> : '—'}
            </dd>
            <dt>User</dt><dd>{a.user_name ? <Link to={search('user_name', a.user_name)}>{a.user_name}</Link> : '—'}</dd>
          </dl>
        </div>
        <div className="card">
          <h2>MITRE ATT&CK</h2>
          <dl className="kv">
            <dt>Technique</dt>
            <dd>
              {technique
                ? <a href={technique} target="_blank" rel="noreferrer noopener">{a.attack_technique} · {a.attack_name} ↗</a>
                : '—'}
            </dd>
            <dt>Tactics</dt>
            <dd>{a.attack_tactics.map((t) => <span className="tag" key={t}>{t}</span>)}</dd>
            {rule && <>
              <dt>Rule</dt><dd><span className="mono">{rule.id}</span> ({rule.type})</dd>
              <dt>Logic</dt>
              <dd>
                {rule.type === 'threshold' && <>≥ {rule.threshold} matching events per {rule.group_by.join(', ')} within {fmtSecs(rule.timeframe_seconds)}</>}
                {rule.type === 'sequence' && <>≥ {rule.threshold} failures then a success per {rule.group_by.join(', ')} within {fmtSecs(rule.timeframe_seconds)}</>}
                {rule.type === 'first_seen' && <>New value for {rule.group_by.join(', ')} after a baseline exists</>}
                {rule.type === 'match' && <>Any single matching event</>}
              </dd>
            </>}
          </dl>
          {rule?.description && <p className="subtle" style={{ marginBottom: 0 }}>{rule.description}</p>}
        </div>
      </div>

      <div className="card">
        <h2>Triggering events ({a.events.length})</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>{EVENT_COLUMNS.map((c) => <th key={c}>{c.replace('event_', '').replace('_', ' ')}</th>)}<th>Raw log</th></tr>
            </thead>
            <tbody>
              {a.events.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap">{formatTime(e.timestamp)}</td>
                  <td className="nowrap">{e.event_action}</td>
                  <td>{e.event_outcome || '—'}</td>
                  <td>{e.user_name || '—'}</td>
                  <td className="mono nowrap">{e.source_ip || '—'}</td>
                  <td className="raw">{e.raw}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
