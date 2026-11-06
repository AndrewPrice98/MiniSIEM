import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { Empty, ErrorState, Loading, Pager, formatTime, useAsync } from '../components/ui.jsx'

const LIMIT = 50
const TEXT_FILTERS = [
  ['host', 'Host'],
  ['user_name', 'User'],
  ['source_ip', 'Source IP'],
]
const SELECT_FILTERS = [
  ['source_type', 'Source'],
  ['event_action', 'Action'],
  ['event_outcome', 'Outcome'],
]
const ALL_KEYS = ['q', 'start', 'end', ...TEXT_FILTERS.map((f) => f[0]), ...SELECT_FILTERS.map((f) => f[0])]

// <input type="datetime-local"> works in local time; the API speaks UTC. Treat
// the input as UTC so it matches the timestamps shown everywhere else.
const toInput = (iso) => (iso ? iso.slice(0, 16) : '')
const fromInput = (v) => (v ? `${v}:00Z` : '')

export default function Events() {
  const [params, setParams] = useSearchParams()
  const offset = Number(params.get('offset') || 0)
  const applied = Object.fromEntries(ALL_KEYS.map((k) => [k, params.get(k) || '']))
  const [draft, setDraft] = useState(applied)

  // Keep the form in sync when the URL changes (e.g. arriving from a link).
  useEffect(() => { setDraft(applied) }, [params.toString()]) // eslint-disable-line react-hooks/exhaustive-deps

  const facets = useAsync(() => api.facets(), [])
  const events = useAsync(() => api.events({ ...applied, limit: LIMIT, offset }), [params.toString()])

  function apply(values, nextOffset = 0) {
    const next = new URLSearchParams()
    for (const [k, v] of Object.entries(values)) if (v) next.set(k, v)
    if (nextOffset) next.set('offset', nextOffset)
    setParams(next, { replace: false })
  }

  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value })
  const active = ALL_KEYS.some((k) => applied[k])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Event search</h1>
          <div className="subtle">Every normalized event, with its original log line. Times are UTC.</div>
        </div>
      </div>

      <div className="card">
        <form className="filters" onSubmit={(e) => { e.preventDefault(); apply(draft) }}>
          <label className="field" style={{ flex: '1 1 220px' }}>Keyword (raw log contains)
            <input type="search" value={draft.q} onChange={set('q')} placeholder="e.g. Failed password" maxLength={200} />
          </label>
          <label className="field">From (UTC)
            <input type="datetime-local" value={toInput(draft.start)}
              onChange={(e) => setDraft({ ...draft, start: fromInput(e.target.value) })} />
          </label>
          <label className="field">To (UTC)
            <input type="datetime-local" value={toInput(draft.end)}
              onChange={(e) => setDraft({ ...draft, end: fromInput(e.target.value) })} />
          </label>
          {TEXT_FILTERS.map(([k, label]) => (
            <label className="field" key={k}>{label}
              <input value={draft[k]} onChange={set(k)} placeholder="any" size={12} />
            </label>
          ))}
          {SELECT_FILTERS.map(([k, label]) => (
            <label className="field" key={k}>{label}
              <select value={draft[k]} onChange={set(k)}>
                <option value="">Any</option>
                {facets.data?.[k]?.map((v) => <option key={v} value={v}>{v}</option>)}
                {draft[k] && !facets.data?.[k]?.includes(draft[k]) && <option value={draft[k]}>{draft[k]}</option>}
              </select>
            </label>
          ))}
          <button className="primary" type="submit">Search</button>
          {active && <button type="button" className="link" onClick={() => apply({})}>Clear</button>}
        </form>

        {events.loading && !events.data && <Loading />}
        {events.error && <ErrorState error={events.error} onRetry={events.reload} />}
        {events.data && events.data.total === 0 && (
          <Empty>{active ? 'No events match this search.' : 'No events yet. Ingest some logs first.'}</Empty>
        )}
        {events.data && events.data.total > 0 && (
          <>
            <div className="table-wrap" style={{ opacity: events.loading ? 0.6 : 1 }}>
              <table>
                <thead>
                  <tr>
                    <th>Time</th><th>Source</th><th>Host</th><th>Action</th><th>Outcome</th>
                    <th>User</th><th>Source IP</th><th>Raw log</th>
                  </tr>
                </thead>
                <tbody>
                  {events.data.items.map((e) => (
                    <tr key={e.id}>
                      <td className="nowrap">{formatTime(e.timestamp)}</td>
                      <td>{e.source_type}</td>
                      <td className="nowrap">{e.host || '—'}</td>
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
            <Pager total={events.data.total} limit={LIMIT} offset={offset} onChange={(o) => apply(applied, o)} />
          </>
        )}
      </div>
    </>
  )
}
