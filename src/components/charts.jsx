import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

const H = 170
const PAD = { top: 8, right: 4, bottom: 22, left: 34 }

function niceMax(v) {
  if (v <= 5) return 5
  const mag = 10 ** Math.floor(Math.log10(v))
  const step = [1, 2, 2.5, 5, 10].find((s) => s * mag >= v / 4) * mag
  return Math.ceil(v / step) * step
}

function bucketLabel(iso, bucket) {
  return bucket === 'hour' ? iso.slice(11, 16) : iso.slice(5, 10)
}

/**
 * Stacked bars of events per time bucket: failures on the baseline, other events above.
 * Hover any column for the exact numbers.
 */
export function TimelineChart({ timeline, bucket }) {
  const [hover, setHover] = useState(null)
  // Draw at the container's real pixel width so text and bars never get scaled up.
  const boxRef = useRef(null)
  const [W, setW] = useState(720)
  useEffect(() => {
    const el = boxRef.current
    if (!el) return undefined
    const ro = new ResizeObserver(([entry]) => setW(Math.max(280, Math.round(entry.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [Boolean(timeline?.length)]) // eslint-disable-line react-hooks/exhaustive-deps
  if (!timeline?.length) return null

  const max = niceMax(Math.max(...timeline.map((b) => b.events)))
  const innerW = W - PAD.left - PAD.right
  const innerH = H - PAD.top - PAD.bottom
  const slot = innerW / timeline.length
  const barW = Math.max(2, slot - 2) // 2px surface gap between bars
  const y = (v) => PAD.top + innerH - (v / max) * innerH
  const ticks = [0, max / 2, max]
  const labelEvery = Math.ceil(timeline.length / 8)
  const r = Math.min(1, barW / 2) // square-ish ends to match the console theme

  // A bar with only the top end rounded, anchored to the baseline.
  const roundedTop = (x, top, h) =>
    h <= 0 ? '' : h < r
      ? `M${x},${top + h}V${top}H${x + barW}V${top + h}Z`
      : `M${x},${top + h}V${top + r}Q${x},${top} ${x + r},${top}H${x + barW - r}Q${x + barW},${top} ${x + barW},${top + r}V${top + h}Z`

  const hovered = hover !== null ? timeline[hover] : null

  return (
    <div className="chart" ref={boxRef}>
      <div className="legend">
        <span><i className="swatch" style={{ background: 'var(--series-2)' }} /> Failed events</span>
        <span><i className="swatch" style={{ background: 'var(--series-1)' }} /> Other events</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img"
        aria-label={`Events per ${bucket}; peak ${Math.max(...timeline.map((b) => b.events))} events`}
        onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD.left} x2={W - PAD.right} y1={y(t)} y2={y(t)}
              stroke={t === 0 ? 'var(--axis)' : 'var(--grid)'} strokeWidth="1" />
            <text x={PAD.left - 6} y={y(t) + 4} textAnchor="end" fontSize="10" fill="var(--muted)"
              style={{ fontVariantNumeric: 'tabular-nums' }}>{t}</text>
          </g>
        ))}
        {timeline.map((b, i) => {
          const x = PAD.left + i * slot + 1
          const other = b.events - b.failures
          const failTop = y(b.failures)
          const failH = PAD.top + innerH - failTop
          const otherTop = y(b.events)
          // 2px surface gap between the two stacked segments
          const otherH = Math.max(0, failTop - otherTop - (b.failures > 0 && other > 0 ? 2 : 0))
          const dim = hover !== null && hover !== i
          return (
            <g key={b.bucket} opacity={dim ? 0.45 : 1}>
              {b.failures > 0 && (
                <path d={other > 0 ? `M${x},${failTop}h${barW}v${failH}h${-barW}Z` : roundedTop(x, failTop, failH)}
                  fill="var(--series-2)" />
              )}
              {other > 0 && <path d={roundedTop(x, otherTop, otherH)} fill="var(--series-1)" />}
              {i % labelEvery === 0 && (
                <text x={x + barW / 2} y={H - 8} textAnchor="middle" fontSize="10" fill="var(--muted)">
                  {bucketLabel(b.bucket, bucket)}
                </text>
              )}
              {/* hit target: the whole column, larger than the mark */}
              <rect x={PAD.left + i * slot} y={PAD.top} width={slot} height={innerH} fill="transparent"
                onMouseEnter={() => setHover(i)} />
            </g>
          )
        })}
      </svg>
      {hovered && (
        <div className="tooltip" style={{
          left: `${((PAD.left + (hover + 0.5) * slot) / W) * 100}%`,
          top: `${(y(hovered.events) / H) * 100}%`,
        }}>
          <div><strong>{hovered.bucket.replace('T', ' ').slice(0, bucket === 'hour' ? 16 : 10)} UTC</strong></div>
          <div className="row"><span>Events</span><strong>{hovered.events}</strong></div>
          <div className="row"><span><i className="swatch" style={{ background: 'var(--series-2)' }} /> Failed</span><strong>{hovered.failures}</strong></div>
          <div className="row"><span>Alerts raised</span><strong>{hovered.alerts}</strong></div>
        </div>
      )}
    </div>
  )
}

/** Ranked horizontal bars with the value written out, linking to a filtered view. */
export function BarList({ items, valueKey, to, extra }) {
  if (!items?.length) return <div className="muted">No data.</div>
  const max = Math.max(...items.map((i) => i[valueKey]))
  return (
    <div className="bar-list">
      {items.map((item) => (
        <div className="bar-row" key={item.value}>
          <Link to={to(item)} className="mono">{item.value}</Link>
          <div className="track" title={`${item[valueKey]}`}>
            <div className="fill" style={{ width: `${(item[valueKey] / max) * 100}%` }} />
          </div>
          <span className="num">{item[valueKey]}{extra ? <> {extra(item)}</> : null}</span>
        </div>
      ))}
    </div>
  )
}
