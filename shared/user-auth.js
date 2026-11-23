// Checks user logins in EVERY service (the admin service issues them, all services verify them).
//  1. Authorization: Bearer <JWT> signed with RS256 by the admin service (private key only there).
//  2. Signature checked with the PUBLIC key from Secrets Manager (other services cannot sign logins).
//  3. The account's current state is checked on every protected request (cached 10 s), so a
//     banned or suspended user is stopped even while their token has not expired, and a token
//     from before a logout/ban (old token version) is refused.
const jwt = require('jsonwebtoken');
const { getSecret } = require('./secrets');
const { errors } = require('./http');

const ISSUER = 'roadhub-admin';
const AUDIENCE = 'roadhub-api';

async function publicKey() {
  const { PUBLIC_KEY } = await getSecret('roadhub/jwt-public');
  return PUBLIC_KEY;
}

function effectiveStatus(status) {
  if (status.accountStatus === 'suspended' && status.suspendedUntil && new Date(status.suspendedUntil) <= new Date()) {
    return 'active'; // a suspension ends by itself
  }
  return status.accountStatus;
}

// getStatus(userId, requestId) -> { role, accountStatus, tokenVersion, suspendedUntil } or null
function createUserAuth({ getStatus, cacheMs }) {
  const ttl = cacheMs !== undefined ? cacheMs : Number(process.env.USER_STATUS_CACHE_MS || 10000);
  const cache = new Map();

  async function statusOf(userId, requestId) {
    const hit = cache.get(userId);
    if (hit && hit.expires > Date.now()) return hit.status;
    const status = await getStatus(userId, requestId);
    if (cache.size > 10000) cache.clear();
    if (status && ttl > 0) cache.set(userId, { status, expires: Date.now() + ttl });
    return status;
  }

  async function authenticate(req) {
    const header = req.get('Authorization') || '';
    const match = header.match(/^Bearer ([A-Za-z0-9._-]{20,4096})$/);
    if (!match) throw errors.unauthenticated();
    let claims;
    try {
      claims = jwt.verify(match[1], await publicKey(), { algorithms: ['RS256'], issuer: ISSUER, audience: AUDIENCE });
    } catch {
      throw errors.unauthenticated('Your session is not valid. Please log in again.');
    }
    if (claims.typ !== 'user') throw errors.unauthenticated('Your session is not valid. Please log in again.');
    const status = await statusOf(claims.sub, req.id);
    if (!status || (status.tokenVersion || 0) !== claims.tv) {
      throw errors.unauthenticated('Your session has ended. Please log in again.');
    }
    const accountStatus = effectiveStatus(status);
    if (accountStatus === 'banned') throw errors.forbidden('ACCOUNT_BANNED', 'This account is banned.');
    req.user = { id: claims.sub, role: status.role, name: claims.name, accountStatus };
    return req.user;
  }

  // Protected route. A suspended user may still READ (GET) but not change anything.
  function requireUser(req, res, next) {
    authenticate(req).then((user) => {
      if (user.accountStatus === 'suspended' && req.method !== 'GET') {
        return next(errors.forbidden('ACCOUNT_SUSPENDED', 'This account is suspended and can only read.'));
      }
      next();
    }, next);
  }

  // Public route that shows extra details to a logged-in user (no error when logged out).
  function optionalUser(req, res, next) {
    if (!req.get('Authorization')) return next();
    authenticate(req).then(() => next(), () => next());
  }

  // Logged in with any non-banned account (used by logout, so a suspended user can still log out).
  function requireSession(req, res, next) {
    authenticate(req).then(() => next(), next);
  }

  function requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user || !roles.includes(req.user.role)) return next(errors.forbidden('FORBIDDEN', 'Your role is not allowed to do this.'));
      next();
    };
  }

  return { requireUser, requireSession, optionalUser, requireRole, clearCache: () => cache.clear() };
}

module.exports = { createUserAuth, effectiveStatus, ISSUER, AUDIENCE };
