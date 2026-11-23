// Used by the Roadmap and Engagement services: asks the Administration Service (owner of the
// accounts) for a user's current state over HTTP. If it cannot answer, the request is refused
// (fail closed: better a 503 than letting a banned user through).
const { errors } = require('./http');

function remoteStatusFetcher(client) {
  return async (userId, requestId) => {
    const out = await client.call('admin', {
      path: `/internal/identity/users/${encodeURIComponent(userId)}/status`, scope: 'identity:read', requestId
    });
    if (out.status === 404) return null;
    if (out.status !== 200) throw errors.unavailable();
    return out.data;
  };
}

module.exports = { remoteStatusFetcher };
