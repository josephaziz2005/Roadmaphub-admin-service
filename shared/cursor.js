// Pagination cursors: DynamoDB's LastEvaluatedKey turned into an opaque text for the URL.
const { errors } = require('./http');

const encode = (key) => (key ? Buffer.from(JSON.stringify(key)).toString('base64url') : undefined);

function decode(text) {
  if (!text) return undefined;
  try {
    const key = JSON.parse(Buffer.from(String(text), 'base64url').toString('utf8'));
    if (!key || typeof key !== 'object' || Array.isArray(key)) throw new Error('bad');
    return key;
  } catch {
    throw errors.badRequest('cursor is not valid.', { field: 'cursor' });
  }
}

module.exports = { encode, decode };
