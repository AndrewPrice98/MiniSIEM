// Thin wrapper around the MiniSIEM REST API.

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`/api${path}`, options)
  } catch {
    throw new Error('Cannot reach the MiniSIEM API. Is the backend running on port 8000?')
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch { /* not JSON */ }
    throw new Error(detail)
  }
  return res.json()
}

export function qs(params) {
  const sp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value)) value.forEach((v) => sp.append(key, v))
    else sp.append(key, value)
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

export const api = {
  health: () => request('/health'),
  stats: (params = {}) => request(`/stats${qs(params)}`),
  alerts: (params = {}) => request(`/alerts${qs(params)}`),
  alert: (id) => request(`/alerts/${encodeURIComponent(id)}`),
  events: (params = {}) => request(`/events${qs(params)}`),
  facets: () => request('/events/facets'),
  rules: () => request('/rules'),
  detect: () => request('/detect', { method: 'POST' }),
  ingest: (formData) => request('/ingest', { method: 'POST', body: formData }),
}
