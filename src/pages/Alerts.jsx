import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { Empty, ErrorState, Loading, Pager, SEVERITIES, Severity, formatTime, useAsync } from '../components/ui.jsx'

const LIMIT = 25
const COLUMNS = [
  ['severity', 'Severity'],
  [null, 'Alert'],
  ['rule_id', 'Rule'],
  ['host', 'Host'],
  ['source_ip', 'Source IP'],
  ['event_count', 'Events'],
  ['first_seen', 'First seen (UTC)'],
  ['status', 'Status'],
]
const FILTER_KEYS = ['rule_id', 'host', 'source_ip', 'user_name', 'technique', 'q']

export default function Alerts({ demo }) {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const severity = params.getAll('severity')
  const sort = params.get('sort') || 'first_seen'
  const order = params.get('order') || 'desc'
  const offset = Number(params.get('offset') || 0)
  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) || '']))

  const rules = useAsync(() => api.rules(), [])
  const alerts = useAsync(
    () => api.alerts({ ...filters, severity, sort, order, limit: LIMIT, offset }),
    [params.toString()],
    { pollMs: demo ? 15000 : 0 },
  )

  function update(changes, { resetPage = true } = {}) {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(changes)) {
      next.delete(k)
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x))
      else if (v !== '' && v != null) next.set(k, v)
    }
    if (resetPage) next.delete('offset')
    setParams(next, { replace: true })
  }

  function toggleSeverity(s) {
    update({ severity: severity.includes(s) ? severity.filter((x) => x !== s) : [...severity, s] })
  }

  function sortBy(col) {
    update({ sort: col, order: sort === col && order === 'desc' ? 'asc' : 'desc' })
  }

  const active = severity.length > 0 || FILTER_KEYS.some((k) => filters[k])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <div className="subtle">Everything the detection rules have raised.</div>
        </div>
      </div>

      <div className="card">
        <div className="filters">
          <div className="field">Severity
            <div className="chips" role="group" aria-label="Severity">
              {SEVERITIES.map((s) => (
                <button key={s} type="button" className="chip" aria-pressed={severity.includes(s)}
                  onClick={() => toggleSeverity(s)}>
                  <Severity level={s} />
                </button>
              ))}
            </div>
          </div>
          <label className="field">Rule
            <select value={filters.rule_id} onChange={(e) => update({ rule_id: e.target.value })}>
              <option value="">All rules</option>
              {rules.data?.map((r) => <option key={r.id} value={r.id}>{r.id} · {r.title}</option>)}
            </select>
          </label>
          <label className="field">Source IP
            <input value={filters.source_ip} placeholder="any" size={14}
              onChange={(e) => update({ source_ip: e.target.value.trim() })} />
          </label>
          <label className="field">Search summary
            <input type="search" value={filters.q} placeholder="e.g. deploy" size={16}
              onChange={(e) => update({ q: e.target.value })} />
          </label>
          {active && (
            <button type="button" className="link" onClick={() => setParams({}, { replace: true })}>
              Clear filters
            </button>
          )}
        </div>
        {(filters.host || filters.user_name || filters.technique) && (
          <div className="subtle" style={{ fontSize: 12, marginBottom: 8 }}>
            Also filtered by{' '}
            {['host', 'user_name', 'technique'].filter((k) => filters[k]).map((k) => (
              <span className="tag" key={k}>{k.replace('_', ' ')}: {filters[k]}</span>
            ))}
          </div>
        )}

        {alerts.loading && !alerts.data && <Loading />}
        {alerts.error && <ErrorState error={alerts.error} onRetry={alerts.reload} />}
        {alerts.data && alerts.data.total === 0 && (
          <Empty>{active ? 'No alerts match these filters.' : 'No alerts yet. Ingest some logs first.'}</Empty>
        )}
        {alerts.data && alerts.data.total > 0 && (
          <>
            <div className="table-wrap" style={{ opacity: alerts.loading ? 0.6 : 1 }}>
              <table>
                <thead>
                  <tr>
                    {COLUMNS.map(([key, label]) => (
                      <th key={label} aria-sort={sort === key ? (order === 'asc' ? 'ascending' : 'descending') : undefined}>
                        {key ? (
                          <button onClick={() => sortBy(key)}>
                            {label}<span aria-hidden="true">{sort === key ? (order === 'asc' ? '↑' : '↓') : ''}</span>
                          </button>
                        ) : label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alerts.data.items.map((a) => (
                    <tr key={a.id} className="clickable" onClick={() => navigate(`/alerts/${a.id}`)}>
                      <td><Severity level={a.severity} /></td>
                      <td>
                        <a href={`/alerts/${a.id}`} onClick={(e) => { e.preventDefault(); navigate(`/alerts/${a.id}`) }}>
                          {a.summary}
                        </a>
                        <div className="muted" style={{ fontSize: 11 }}>{a.rule_title} · <span className="mono">{a.attack_technique}</span></div>
                      </td>
                      <td className="nowrap mono">{a.rule_id}</td>
                      <td className="nowrap">{a.host || '—'}</td>
                      <td className="nowrap mono">{a.source_ip || '—'}</td>
                      <td className="num">{a.event_count}</td>
                      <td className="ts">{formatTime(a.first_seen)}</td>
                      <td>{a.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager total={alerts.data.total} limit={LIMIT} offset={offset}
              onChange={(o) => update({ offset: o }, { resetPage: false })} />
          </>
        )}
      </div>
    </>
  )
}
