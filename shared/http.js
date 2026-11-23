// Express helpers shared by the three services: error shape, request ids,
// security headers, JSON-only bodies and the central error handler.
const { randomUUID } = require('crypto');
const logger = require('./logger');

// Every error answer has the same shape (Lab 3/4): { "error": { "code", "message", "details"? } }
class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const errors = {
  badRequest: (message, details) => new AppError(400, 'VALIDATION_ERROR', message, details),
  unauthenticated: (message = 'Please log in first.') => new AppError(401, 'UNAUTHENTICATED', message),
  forbidden: (code = 'FORBIDDEN', message = 'You are not allowed to do this.') => new AppError(403, code, message),
  notFound: (code = 'NOT_FOUND', message = 'Not found.') => new AppError(404, code, message),
  conflict: (code, message, details) => new AppError(409, code, message, details),
  tooMany: (message = 'Too many requests. Please wait and try again.') => new AppError(429, 'RATE_LIMITED', message),
  unavailable: (code = 'DEPENDENCY_UNAVAILABLE', message = 'A required service is not available. Please try again.') =>
    new AppError(503, code, message)
};

function sendError(res, status, code, message, details) {
  const body = { error: { code, message } };
  if (details !== undefined) body.error.details = details;
  return res.status(status).json(body);
}

// Re-use the caller's X-Request-Id (so one user action can be followed across services), or make one.
const REQUEST_ID = /^[A-Za-z0-9-]{8,64}$/;
function requestId(req, res, next) {
  const incoming = req.get('X-Request-Id');
  req.id = incoming && REQUEST_ID.test(incoming) ? incoming : randomUUID();
  res.set('X-Request-Id', req.id);
  next();
}

function requestLogger(req, res, next) {
  const started = process.hrtime.bigint();
  res.on('finish', () => {
    logger.info('REQUEST', {
      requestId: req.id,
      method: req.method,
      path: req.originalUrl.split('?')[0],
      status: res.statusCode,
      userId: req.user ? req.user.id : undefined,
      caller: req.caller ? req.caller.service : undefined,
      ms: Number((process.hrtime.bigint() - started) / 1000000n)
    });
  });
  next();
}

function securityHeaders(req, res, next) {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Cache-Control': 'no-store'
  });
  next();
}

// A body that is sent must be JSON (Lab 4: 415 otherwise).
function requireJson(req, res, next) {
  const hasBody = Number(req.get('Content-Length') || 0) > 0 || req.get('Transfer-Encoding');
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && hasBody && !req.is('application/json')) {
    return sendError(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.');
  }
  next();
}

function notFound(req, res) {
  sendError(res, 404, 'ROUTE_NOT_FOUND', 'This route does not exist.');
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed') return sendError(res, 400, 'VALIDATION_ERROR', 'The body is not valid JSON.');
  if (err.type === 'entity.too.large') return sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'The body is too large.');
  if (err instanceof AppError) {
    if (err.status === 401 || err.status === 403) {
      logger.security(err.status === 401 ? 'AUTH_FAILED' : 'ACCESS_DENIED', {
        requestId: req.id, method: req.method, path: req.originalUrl.split('?')[0], code: err.code,
        userId: req.user ? req.user.id : undefined, ip: req.ip
      });
    }
    return sendError(res, err.status, err.code, err.message, err.details);
  }
  logger.error('UNHANDLED_ERROR', { requestId: req.id, path: req.originalUrl.split('?')[0], name: err.name, message: err.message });
  return sendError(res, 500, 'INTERNAL_ERROR', 'Something went wrong. Please try again.');
}

module.exports = { AppError, errors, sendError, requestId, requestLogger, securityHeaders, requireJson, notFound, errorHandler };
