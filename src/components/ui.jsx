import { useCallback, useEffect, useState } from 'react'

export const SEVERITIES = ['critical', 'high', 'medium', 'low']

const SEV_SHORT = { critical: 'crit', high: 'high', medium: 'med', low: 'low' }

/** Severity tag: colored bar plus a text label, so it never relies on color alone. */
export function Severity({ level }) {
  return <span className={`sev ${level}`} title={level}>{SEV_SHORT[level] || level}</span>
}

export function Loading({ label = 'Loading…' }) {
  return <div className="state" role="status">{label}</div>
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="state error" role="alert">
      <strong>Something went wrong.</strong> {error?.message || String(error)}
      {onRetry && <> <button className="link" onClick={onRetry}>Try again</button></>}
    </div>
  )
}

export function Empty({ children }) {
  return <div className="state">{children}</div>
}

/**
 * Run an async loader whenever deps change. Ignores stale responses.
 * With pollMs, also refetch quietly on that interval while the tab is visible: no
 * loading flag, and a failed refresh keeps the data already on screen.
 */
export function useAsync(loader, deps, { pollMs = 0 } = {}) {
  const [state, setState] = useState({ loading: true, error: null, data: null })
  const [tick, setTick] = useState(0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(loader, deps)
  useEffect(() => {
    let live = true
    setState((s) => ({ ...s, loading: true, error: null }))
    load()
      .then((data) => live && setState({ loading: false, error: null, data }))
      .catch((error) => live && setState({ loading: false, error, data: null }))
    return () => { live = false }
  }, [load, tick])
  useEffect(() => {
    if (!pollMs) return undefined
    let live = true
    const id = setInterval(() => {
      if (document.visibilityState !== 'visible') return
      load().then((data) => live && setState({ loading: false, error: null, data })).catch(() => {})
    }, pollMs)
    return () => { live = false; clearInterval(id) }
  }, [load, pollMs])
  return { ...state, reload: () => setTick((t) => t + 1) }
}

/** All times in the UI are UTC; column headers and page subtitles say so. */
export function formatTime(iso, { seconds = true } = {}) {
  if (!iso) return '—'
  const d = iso.replace('T', ' ').replace('Z', '')
  return seconds ? d : d.slice(0, 16)
}

export function Pager({ total, limit, offset, onChange }) {
  if (total <= limit) return <div className="pager">{total} result{total === 1 ? '' : 's'}</div>
  const from = offset + 1
  const to = Math.min(offset + limit, total)
  return (
    <div className="pager">
      <span className="num">{from}–{to} of {total}</span>
      <button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
      <button disabled={to >= total} onClick={() => onChange(offset + limit)}>Next</button>
    </div>
  )
}

export function attackUrl(technique) {
  if (!technique) return null
  return `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`
}
