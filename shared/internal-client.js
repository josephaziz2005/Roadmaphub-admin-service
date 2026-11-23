// HTTP client for calls between services (real REST calls, not JavaScript imports).
//   - signs a fresh service token for each call (aud = target service, limited scope)
//   - forwards X-Request-Id so one user action can be traced through every service log
//   - 3 s timeout; retries only when it is safe (GET, or a call with an Idempotency-Key)
const { signServiceToken } = require('./internal-auth');
const { errors, AppError } = require('./http');
const logger = require('./logger');

const DEFAULT_URLS = {
  roadmap: process.env.ROADMAP_URL || 'http://127.0.0.1:3001',
  engagement: process.env.ENGAGEMENT_URL || 'http://127.0.0.1:3002',
  admin: process.env.ADMIN_URL || 'http://127.0.0.1:3003'
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createInternalClient(self, urls = DEFAULT_URLS) {
  async function call(target, { method = 'GET', path, body, scope, requestId, idempotencyKey, timeoutMs = 3000 }) {
    const safeToRetry = method === 'GET' || Boolean(idempotencyKey);
    const attempts = safeToRetry ? 3 : 1;
    let lastProblem;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const headers = {
          'X-Service-Token': await signServiceToken({ from: self, to: target, scope }),
          Accept: 'application/json'
        };
        if (requestId) headers['X-Request-Id'] = requestId;
        if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
        if (body !== undefined) headers['Content-Type'] = 'application/json';

        const response = await fetch(`${urls[target]}${path}`, {
          method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal
        });
        const text = await response.text();
        const data = text ? JSON.parse(text) : null;
        if (response.status >= 500 && attempt < attempts) {
          lastProblem = `status ${response.status}`;
        } else {
          return { status: response.status, data };
        }
      } catch (e) {
        lastProblem = e.name === 'AbortError' ? 'timeout' : e.message;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < attempts) await sleep(attempt * 150);
    }
    logger.warn('INTERNAL_CALL_FAILED', { requestId, target, method, path: path.split('?')[0], problem: lastProblem });
    throw errors.unavailable();
  }

  // Helper: throw the target's own error (for example 404 or 409) as an AppError.
  // A 5xx from the target becomes 503 here: its internal error is never passed on to the user.
  async function callOk(target, options) {
    const out = await call(target, options);
    if (out.status >= 500) {
      logger.warn('INTERNAL_CALL_FAILED', { requestId: options.requestId, target, method: options.method || 'GET', path: options.path.split('?')[0], problem: `status ${out.status}` });
      throw errors.unavailable();
    }
    if (out.status >= 400) {
      const err = (out.data && out.data.error) || {};
      throw new AppError(out.status, err.code || 'DEPENDENCY_ERROR', err.message || 'A required service refused the request.', err.details);
    }
    return out.data;
  }

  return { call, callOk };
}

module.exports = { createInternalClient, DEFAULT_URLS };
