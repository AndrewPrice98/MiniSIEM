import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Empty, ErrorState, Loading, Severity, attackUrl, useAsync } from '../components/ui.jsx'

// MITRE ATT&CK Enterprise tactics, in kill-chain order.
const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

// Sequential blue ramp: more alerts = darker. Covered-but-quiet techniques sit at step 0.
const STEPS = [
  { min: 0, bg: 'var(--seq-0)', ink: 'var(--ink)', label: '0 (covered)' },
  { min: 1, bg: 'var(--seq-1)', ink: '#0b0b0b', label: '1' },
  { min: 2, bg: 'var(--seq-2)', ink: '#0b0b0b', label: '2–3' },
  { min: 4, bg: 'var(--seq-3)', ink: '#ffffff', label: '4–6' },
  { min: 7, bg: 'var(--seq-4)', ink: '#ffffff', label: '7–9' },
  { min: 10, bg: 'var(--seq-5)', ink: '#ffffff', label: '10+' },
]
const stepFor = (n) => [...STEPS].reverse().find((s) => n >= s.min)

function buildMatrix(rules) {
  // technique -> { id, name, alerts, rules[] }, placed under each of its tactics
  const techniques = {}
  for (const r of rules) {
    if (!r.attack_technique) continue
    const t = (techniques[r.attack_technique] ||= {
      id: r.attack_technique, name: r.attack_name, alerts: 0, rules: [], tactics: new Set(),
    })
    t.alerts += r.alert_count
    t.rules.push(r)
    r.attack_tactics.forEach((x) => t.tactics.add(x))
  }
  return TACTICS.map((tactic) => ({
    tactic,
    techniques: Object.values(techniques)
      .filter((t) => t.tactics.has(tactic))
      .sort((a, b) => b.alerts - a.alerts || a.id.localeCompare(b.id)),
  }))
}

export default function Attack() {
  const { data: rules, loading, error, reload } = useAsync(() => api.rules(), [])

  if (loading && !rules) return <Loading />
  if (error) return <ErrorState error={error} onRetry={reload} />
  if (!rules.length) return <Empty>No detection rules loaded.</Empty>

  const matrix = buildMatrix(rules)
  const covered = new Set(rules.map((r) => r.attack_technique)).size
  const detected = new Set(rules.filter((r) => r.alert_count > 0).map((r) => r.attack_technique)).size
  const tacticsCovered = matrix.filter((c) => c.techniques.length).length

  return (
    <>
      <div className="page-head">
        <div>
          <h1>ATT&CK coverage</h1>
          <div className="subtle">
            {covered} techniques across {tacticsCovered} of {TACTICS.length} tactics have a rule;{' '}
            {detected} have fired. Darker = more alerts.
          </div>
        </div>
        <div className="scale" aria-label="Color scale: alerts per technique">
          Alerts:
          {STEPS.map((s) => (
            <span key={s.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginRight: 6 }}>
              <i className="swatch" style={{ background: s.bg, border: '1px solid var(--border)' }} />{s.label}
            </span>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="matrix">
          {matrix.map(({ tactic, techniques }) => (
            <section className="tactic" key={tactic} aria-label={tactic}>
              <h3>{tactic}</h3>
              {techniques.length === 0 && <div className="empty">No rules yet</div>}
              {techniques.map((t) => {
                const step = stepFor(t.alerts)
                return (
                  <Link key={t.id} className="technique" to={`/alerts?technique=${encodeURIComponent(t.id)}`}
                    style={{ background: step.bg, color: step.ink }}
                    title={`${t.id} ${t.name}: ${t.alerts} alert(s) from ${t.rules.map((r) => r.id).join(', ')}`}>
                    <span className="tid">{t.id}</span>
                    {t.name}
                    <span className="count">{t.alerts} alert{t.alerts === 1 ? '' : 's'}</span>
                  </Link>
                )
              })}
            </section>
          ))}
        </div>
      </div>

      <div className="card">
        <h2>Detection rules</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Rule</th><th>Title</th><th>Severity</th><th>Source</th><th>Technique</th><th>Tactics</th><th>Alerts</th></tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td className="mono nowrap">{r.id}</td>
                  <td>{r.title}</td>
                  <td><Severity level={r.severity} /></td>
                  <td>{r.source_type}</td>
                  <td className="nowrap">
                    <a href={attackUrl(r.attack_technique)} target="_blank" rel="noreferrer noopener">{r.attack_technique} ↗</a>
                  </td>
                  <td>{r.attack_tactics.map((t) => <span className="tag" key={t}>{t}</span>)}</td>
                  <td className="num">
                    {r.alert_count > 0 ? <Link to={`/alerts?rule_id=${r.id}`}>{r.alert_count}</Link> : 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
