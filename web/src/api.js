export async function apiRequest(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  }

  const response = await fetch(path, {
    credentials: 'include',
    ...options,
    headers
  })

  const text = await response.text()
  let payload = null

  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = text
    }
  }

  if (!response.ok) {
    const message =
      (payload && typeof payload === 'object' && payload.error) ||
      response.statusText ||
      'request failed'
    throw new Error(message)
  }

  return payload
}

export async function login(username, password) {
  return apiRequest('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  })
}

export async function logout() {
  await apiRequest('/api/logout', { method: 'POST' })
}
