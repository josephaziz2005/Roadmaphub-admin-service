// HTTP layer of the administration functions (all routes need role "admin").
const { validate: v, cursor } = require('../shared');
const mergeService = require('../services/mergeService');
const moderationService = require('../services/moderationService');
const repos = require('../repositories');

// Function 1: duplicate suggestions
async function duplicateSuggestions(req, res) {
  res.status(200).json({ suggestions: await mergeService.suggestions(v.uuid(req.params.id), req.id) });
}

// Function 2: merge a duplicate (:id) into the main request (targetId)
async function merge(req, res) {
  v.onlyFields(req.body, ['targetId']);
  const record = await mergeService.merge(req.user, { sourceId: v.uuid(req.params.id), targetId: v.uuid(req.body.targetId, 'targetId') }, req.ip, req.id);
  res.status(201).json({ merge: mergeService.publicMerge(record) });
}

// Function 3: undo within 7 days
async function undo(req, res) {
  const record = await mergeService.undo(req.user, v.uuid(req.params.mergeId, 'mergeId'), req.ip, req.id);
  res.status(200).json({ merge: mergeService.publicMerge(record) });
}

async function listMerges(req, res) {
  const page = await repos.merges.list({ limit: 50, cursor: cursor.decode(req.query.cursor) });
  res.status(200).json({ items: page.items.map(mergeService.publicMerge), nextCursor: cursor.encode(page.next) });
}

// Moderation
async function listUsers(req, res) {
  const status = req.query.status ? v.oneOf(req.query.status, ['active', 'suspended', 'banned'], 'status') : undefined;
  const q = req.query.q ? v.text(req.query, 'q', { min: 1, max: 60 }) : undefined;
  res.status(200).json({ users: await moderationService.listUsers({ status, q }) });
}

async function changeUserStatus(req, res) {
  v.onlyFields(req.body, ['action', 'days', 'reason']);
  const action = v.oneOf(req.body.action, ['suspend', 'ban', 'restore'], 'action');
  const input = { action };
  if (action === 'suspend') input.days = v.int(req.body.days, 'days', { min: 1, max: 365 });
  if (action !== 'restore') input.reason = v.text(req.body, 'reason', { min: 3, max: 200 });
  if (action === 'suspend' && input.days === undefined) return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'days is required.' } });
  res.status(200).json({ user: await moderationService.changeStatus(req.user, v.uuid(req.params.id), input, req.ip, req.id) });
}

// Monitoring
async function auditLog(req, res) {
  const type = req.query.type ? v.oneOf(req.query.type, ['ACTION', 'SECURITY', 'OPS_ALERT'], 'type') : undefined;
  const page = await repos.audit.list({ limit: 100, type, cursor: cursor.decode(req.query.cursor) });
  res.status(200).json({ items: page.items, nextCursor: cursor.encode(page.next) });
}

// Security events of the last N minutes grouped by address; more than 10 failed logins
// from one address in 15 minutes is flagged as a possible brute-force attack.
async function securityEvents(req, res) {
  const minutes = v.int(req.query.minutes, 'minutes', { min: 1, max: 1440, fallback: 60 });
  const since = new Date(Date.now() - minutes * 60000).toISOString();
  const quarter = new Date(Date.now() - 15 * 60000).toISOString();
  const { items } = await repos.audit.list({ limit: 500, type: 'SECURITY' });
  const recent = items.filter((e) => e.createdAt >= since);
  const byIp = new Map();
  for (const e of recent) {
    const key = e.ip || 'unknown';
    const entry = byIp.get(key) || { ip: key, total: 0, byAction: {}, failedLoginsLast15Min: 0 };
    entry.total += 1;
    entry.byAction[e.action] = (entry.byAction[e.action] || 0) + 1;
    if (e.action === 'LOGIN_FAILED' && e.createdAt >= quarter) entry.failedLoginsLast15Min += 1;
    byIp.set(key, entry);
  }
  const sources = [...byIp.values()].map((s) => ({ ...s, alert: s.failedLoginsLast15Min > 10 })).sort((a, b) => b.total - a.total);
  res.status(200).json({ windowMinutes: minutes, totalEvents: recent.length, alerts: sources.filter((s) => s.alert).length, sources, latest: recent.slice(0, 20) });
}

module.exports = { duplicateSuggestions, merge, undo, listMerges, listUsers, changeUserStatus, auditLog, securityEvents };
