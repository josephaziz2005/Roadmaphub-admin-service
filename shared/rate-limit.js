// Sliding-window rate limiter (Lab 8 idea): at most `max` requests per `windowMs`
// per client IP or per user. Counted in memory, so with 3 replicas each replica counts
// separately (documented limitation; a shared store would make it exact).
const { errors } = require('./http');
const logger = require('./logger');

function createRateLimiter({ name, windowMs = 60000, max = 60, key = 'ip' }) {
  const hits = new Map();
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [k, list] of hits) {
      const kept = list.filter((t) => t > cutoff);
      if (kept.length) hits.set(k, kept); else hits.delete(k);
    }
  }, windowMs).unref();

  return (req, res, next) => {
    if (process.env.RATE_LIMITS === 'off') return next();
    const id = key === 'user' && req.user ? `u:${req.user.id}` : `ip:${req.ip}`;
    const now = Date.now();
    const recent = (hits.get(id) || []).filter((t) => t > now - windowMs);
    if (recent.length >= max) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      logger.security('RATE_LIMITED', { requestId: req.id, limiter: name, path: req.originalUrl.split('?')[0], ip: req.ip, userId: req.user && req.user.id });
      return next(errors.tooMany());
    }
    recent.push(now);
    hits.set(id, recent);
    next();
  };
}

module.exports = { createRateLimiter };
