// Thin wrapper around the MiniSIEM REST API.
//
// Authentication uses an httpOnly session cookie that the browser sends automatically
// with same-origin requests, so no token is ever handled in JavaScript. Any 401 fires
// a "minisiem:unauthorized" event and the app returns to the login screen.

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`/api${path}`, { credentials: 'same-origin', ...options })
  } catch {
    throw new ApiError('Cannot reach the MiniSIEM API.', 0)
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch { /* not JSON */ }
    if (res.status === 401 && !path.startsWith('/auth/')) {
      window.dispatchEvent(new Event('minisiem:unauthorized'))
    }
    throw new ApiError(detail, res.status)
  }
  return res.json()
}

const json = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

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
  me: () => request('/auth/me'),
  login: (username, password) => request('/auth/login', json({ username, password })),
  logout: () => request('/auth/logout', { method: 'POST' }),
  stats: (params = {}) => request(`/stats${qs(params)}`),
  alerts: (params = {}) => request(`/alerts${qs(params)}`),
  alert: (id) => request(`/alerts/${encodeURIComponent(id)}`),
  events: (params = {}) => request(`/events${qs(params)}`),
  facets: () => request('/events/facets'),
  rules: () => request('/rules'),
  detect: () => request('/detect', { method: 'POST' }),
  ingest: (formData) => request('/ingest', { method: 'POST', body: formData }),
}
