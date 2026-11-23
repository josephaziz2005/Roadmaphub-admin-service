// Small fetch wrapper for tests: api(base)('POST', '/api/x', { token, body, headers })
function api(base) {
  return async (method, path, { token, body, headers = {} } = {}) => {
    const h = { ...headers };
    if (token) h.Authorization = `Bearer ${token}`;
    if (body !== undefined) h['Content-Type'] = 'application/json';
    const res = await fetch(`${base}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    return { status: res.status, data, headers: res.headers };
  };
}

const uniqueEmail = (tag = 'user') => `${tag}.${Date.now()}.${Math.floor(Math.random() * 1e6)}@example.com`;

module.exports = { api, uniqueEmail };
