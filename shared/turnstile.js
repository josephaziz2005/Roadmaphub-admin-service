// Cloudflare Turnstile bot check, verified on the BACKEND (the browser result is never trusted).
// The browser sends the widget's one-time token in the X-Turnstile-Token header.
// TURNSTILE_ENABLED=false turns it off for automated local tests only.
const { getSecret } = require('./secrets');
const { errors } = require('./http');
const logger = require('./logger');

async function verify(token, ip) {
  const { TURNSTILE_SECRET_KEY } = await getSecret('roadhub/turnstile');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token, remoteip: ip || '' }),
      signal: controller.signal
    });
    const data = await res.json();
    return Boolean(data.success);
  } finally {
    clearTimeout(timer);
  }
}

async function requireTurnstile(req, res, next) {
  if (process.env.TURNSTILE_ENABLED === 'false') return next();
  const token = req.get('X-Turnstile-Token');
  let passed = false;
  if (token && token.length <= 2048) {
    try {
      passed = await verify(token, req.ip);
    } catch (e) {
      logger.warn('TURNSTILE_UNAVAILABLE', { requestId: req.id, reason: e.name });
      return next(errors.unavailable('BOT_CHECK_UNAVAILABLE', 'The bot check could not be completed. Please try again.'));
    }
  }
  if (!passed) return next(errors.forbidden('BOT_CHECK_FAILED', 'Please complete the bot check and try again.'));
  next();
}

module.exports = { requireTurnstile };
