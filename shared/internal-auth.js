// Service-to-service authentication for /internal/* routes.
// A caller signs a short-lived "service token" (HS256, 60 s) with the internal key from
// Secrets Manager. User tokens are RS256 with another key and typ "user", so a user token
// can never pass this check, and a service token can never be used as a user login.
const { randomUUID } = require('crypto');
const jwt = require('jsonwebtoken');
const { getSecret } = require('./secrets');
const { errors } = require('./http');
const logger = require('./logger');

const INTERNAL_SECRET_NAME = process.env.INTERNAL_SECRET_NAME || 'roadhub/internal';
const SERVICES = ['roadmap', 'engagement', 'admin'];

async function internalKey() {
  const secret = await getSecret(INTERNAL_SECRET_NAME);
  if (!secret.INTERNAL_SIGNING_KEY || secret.INTERNAL_SIGNING_KEY.length < 32) {
    throw new Error('roadhub/internal has no usable INTERNAL_SIGNING_KEY');
  }
  return secret.INTERNAL_SIGNING_KEY;
}

async function signServiceToken({ from, to, scope }) {
  const scopes = Array.isArray(scope) ? scope : [scope];
  return jwt.sign({ typ: 'service', scope: scopes }, await internalKey(), {
    algorithm: 'HS256', issuer: from, audience: to, expiresIn: 60, jwtid: randomUUID()
  });
}

// Middleware factory: requireService('roadmap', 'features:read')
function requireService(self, scope) {
  return async (req, res, next) => {
    const token = req.get('X-Service-Token');
    if (!token) {
      logger.security('INTERNAL_AUTH_MISSING', { requestId: req.id, path: req.path, ip: req.ip });
      return next(errors.unauthenticated('Service token required.'));
    }
    let claims;
    try {
      claims = jwt.verify(token, await internalKey(), { algorithms: ['HS256'], audience: self });
    } catch (e) {
      logger.security('INTERNAL_AUTH_INVALID', { requestId: req.id, path: req.path, reason: e.name, ip: req.ip });
      return next(errors.unauthenticated('Service token is not valid.'));
    }
    if (claims.typ !== 'service' || !SERVICES.includes(claims.iss)) {
      return next(errors.unauthenticated('Service token is not valid.'));
    }
    if (!Array.isArray(claims.scope) || !claims.scope.includes(scope)) {
      return next(errors.forbidden('SCOPE_MISSING', `This call needs the scope ${scope}.`));
    }
    req.caller = { service: claims.iss, tokenId: claims.jti };
    next();
  };
}

module.exports = { signServiceToken, requireService, SERVICES };
