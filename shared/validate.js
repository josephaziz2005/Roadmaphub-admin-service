// Input checks used by every controller. Each one throws a 400 VALIDATION_ERROR with the field name.
const { errors } = require('./http');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/;

function uuid(value, field = 'id') {
  if (typeof value !== 'string' || !UUID.test(value)) throw errors.badRequest(`${field} must be a valid id.`, { field });
  return value.toLowerCase();
}

function text(body, field, { min = 1, max = 1000, required = true } = {}) {
  const value = body ? body[field] : undefined;
  if (value === undefined || value === null || value === '') {
    if (required) throw errors.badRequest(`${field} is required.`, { field });
    return undefined;
  }
  if (typeof value !== 'string') throw errors.badRequest(`${field} must be text.`, { field });
  const trimmed = value.trim();
  if (trimmed.length < min || trimmed.length > max) {
    throw errors.badRequest(`${field} must contain between ${min} and ${max} characters.`, { field });
  }
  return trimmed;
}

function email(body, field = 'email') {
  const value = text(body, field, { min: 6, max: 254 }).toLowerCase();
  if (!EMAIL.test(value)) throw errors.badRequest('email is not a valid e-mail address.', { field });
  return value;
}

function oneOf(value, allowed, field) {
  if (!allowed.includes(value)) throw errors.badRequest(`${field} must be one of: ${allowed.join(', ')}.`, { field });
  return value;
}

function int(value, field, { min, max, fallback } = {}) {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || (min !== undefined && n < min) || (max !== undefined && n > max)) {
    throw errors.badRequest(`${field} must be a whole number between ${min} and ${max}.`, { field });
  }
  return n;
}

// Blocks mass assignment: fields the client is not allowed to set (role, status, userId...) -> 400.
function onlyFields(body, allowed) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw errors.badRequest('The body must be a JSON object.');
  const extra = Object.keys(body).filter((k) => !allowed.includes(k));
  if (extra.length) throw errors.badRequest(`Unexpected field(s): ${extra.join(', ')}.`, { fields: extra });
  return body;
}

module.exports = { uuid, text, email, oneOf, int, onlyFields, UUID };
