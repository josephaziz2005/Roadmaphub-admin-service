// Suspend, ban and restore accounts. The other services see the change within 10 seconds
// (their account-state cache), and a ban also ends every session at once (token version + 1).
const { http, events, userAuth } = require('../shared');
const repos = require('../repositories');

const { errors } = http;

const maskEmail = (email) => {
  const [name, domain] = (email || '').split('@');
  return domain ? `${name.slice(0, 2)}***@${domain}` : '***';
};

function publicUser(u) {
  return {
    userId: u.userId, name: u.name, email: maskEmail(u.email), role: u.role, accountStatus: userAuth.effectiveStatus(u),
    suspendedUntil: u.suspendedUntil, moderationReason: u.moderationReason, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt
  };
}

async function listUsers({ status, q }) {
  const { items } = await repos.users.listUsers({ limit: 200 });
  const query = (q || '').toLowerCase();
  return items.map(publicUser)
    .filter((u) => !status || u.accountStatus === status)
    .filter((u) => !query || u.name.toLowerCase().includes(query) || u.email.toLowerCase().includes(query));
}

async function changeStatus(admin, userId, { action, days, reason }, ip, requestId) {
  if (userId === admin.id) throw errors.forbidden('CANNOT_TARGET_SELF', 'You cannot change your own account.');
  const target = await repos.users.findById(userId);
  if (!target) throw errors.notFound('USER_NOT_FOUND', 'Account not found.');
  if (target.role === 'admin') throw errors.forbidden('CANNOT_TARGET_ADMIN', 'Administrators cannot be suspended or banned here.');

  let updated;
  if (action === 'suspend') {
    const until = new Date(Date.now() + days * 86400000).toISOString();
    updated = await repos.users.setAccountStatus(userId, { accountStatus: 'suspended', suspendedUntil: until, reason, actorId: admin.id });
  } else if (action === 'ban') {
    updated = await repos.users.setAccountStatus(userId, { accountStatus: 'banned', reason, actorId: admin.id, endSessions: true });
  } else {
    if (userAuth.effectiveStatus(target) === 'active') throw errors.conflict('NOT_RESTRICTED', 'This account is already active.');
    updated = await repos.users.setAccountStatus(userId, { accountStatus: 'active', actorId: admin.id });
  }
  const verb = { suspend: 'UserSuspended', ban: 'UserBanned', restore: 'UserRestored' }[action];
  await repos.audit.record({ action: `user.${action}`, actorId: admin.id, targetType: 'user', targetId: userId, details: { days, reason }, ip, requestId });
  await events.publish('admin', verb, { userId, actorId: admin.id, suspendedUntil: updated.suspendedUntil }, { requestId });
  return publicUser(updated);
}

module.exports = { listUsers, changeStatus, publicUser, maskEmail };
