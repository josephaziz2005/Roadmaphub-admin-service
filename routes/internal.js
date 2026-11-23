// Internal routes of the Administration Service, mounted at /internal (service token required).
const express = require('express');
const { internalAuth, validate: v } = require('../shared');
const repos = require('../repositories');

const router = express.Router();
const need = (scope) => internalAuth.requireService('admin', scope);

router.get('/identity/_ping', need('identity:read'), (req, res) => {
  res.status(200).json({ service: 'admin', caller: req.caller.service });
});

// Account state for the other services' login checks (no e-mail, no password hash).
router.get('/identity/users/:id/status', need('identity:read'), async (req, res) => {
  const user = await repos.users.findById(v.uuid(req.params.id));
  if (!user) return res.status(404).json({ error: { code: 'USER_NOT_FOUND', message: 'Account not found.' } });
  res.status(200).json({
    userId: user.userId, role: user.role, accountStatus: user.accountStatus,
    tokenVersion: user.tokenVersion || 0, suspendedUntil: user.suspendedUntil
  });
});

// Names and e-mails for notification e-mails. Only the scope identity:contacts (engagement worker).
router.post('/identity/users/contacts', need('identity:contacts'), async (req, res) => {
  const ids = Array.isArray(req.body.userIds) ? req.body.userIds.slice(0, 50).map((id) => v.uuid(id, 'userIds')) : [];
  const users = await repos.users.findMany(ids);
  res.status(200).json({
    items: users.filter((u) => u.accountStatus !== 'banned').map((u) => ({ userId: u.userId, name: u.name, email: u.email }))
  });
});

module.exports = router;
