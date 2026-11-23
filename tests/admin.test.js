// Administration Service (S3) on its own, part 2: moderation, duplicate suggestions and the MERGE SAGA.
// The real service process + its real tables (Floci), with a FAKE Roadmap Service and a FAKE
// Engagement Service, so the saga's calls, order, scopes, idempotency keys and compensation can be checked.
// Run: npm test   (needs Floci on localhost:4566 and "npm run setup:tables" once)
const test = require('node:test');
const assert = require('node:assert');
const { randomUUID } = require('crypto');
const { requireTables } = require('./helpers/aws');
const { loadKeys, serviceToken } = require('./helpers/keys');
const { startFake } = require('./helpers/fake-service');
const { startService } = require('./helpers/service');
const { api } = require('./helpers/api');
const { newUser, newAdmin, PASSWORD } = require('./helpers/users');

const features = new Map(); // fake roadmap: id -> { title, status, authorId }
const behave = { roadmapPrepare: 'ok', engagementComplete: 'ok' };
let keys; let roadmap; let engagement; let svc; let call;
const u = {};
const f = {};

function feature(title) {
  const id = randomUUID();
  features.set(id, { featureId: id, title, status: 'under_review', authorId: randomUUID() });
  return id;
}
const merge = (who, sourceId, targetId) => call('POST', `/api/admin/features/${sourceId}/merge`, { token: who.token, body: { targetId } });
const sagaCalls = () => [...roadmap.calls.map((c) => ({ ...c, svc: 'roadmap' })), ...engagement.calls.map((c) => ({ ...c, svc: 'engagement' }))]
  .filter((c) => c.path.includes('/merges/'))
  .sort((a, b) => a.seq - b.seq)
  .map((c) => ({ step: `${c.svc}.${c.path.split('/').pop()}`, ...c }));

test.before(async () => {
  await requireTables(['roadhub-users', 'roadhub-merges', 'roadhub-audit']);
  keys = await loadKeys();
  roadmap = await startFake('roadmap', keys.internalKey, [
    {
      method: 'GET',
      path: /^\/internal\/features\/([^/]+)\/resolve$/,
      reply: ({ params: [id] }) => (features.has(id)
        ? { body: { ...features.get(id), canonicalId: id, exists: true, merged: false, locked: false } }
        : { status: 404, body: { error: { code: 'FEATURE_NOT_FOUND', message: 'This feature request does not exist.' } } })
    },
    { method: 'GET', path: /^\/internal\/features\/candidates$/, reply: () => ({ body: { items: [...features.values()].map((x) => ({ ...x, voteCount: 2 })) } }) },
    {
      method: 'POST',
      path: /^\/internal\/features\/merges\/prepare$/,
      reply: ({ body }) => (behave.roadmapPrepare === 'conflict'
        ? { status: 409, body: { error: { code: 'MERGE_CONFLICT', message: 'One of the requests is already merged or is being merged.' } } }
        : { body: { source: features.get(body.sourceId), target: features.get(body.targetId) } })
    },
    { method: 'POST', path: /^\/internal\/features\/merges\/complete$/, reply: () => ({ body: { merged: true } }) },
    { method: 'POST', path: /^\/internal\/features\/merges\/abort$/, reply: () => ({ body: { aborted: true } }) },
    { method: 'POST', path: /^\/internal\/features\/merges\/undo$/, reply: ({ body }) => ({ body: { restored: features.get(body.sourceId) } }) }
  ]);
  engagement = await startFake('engagement', keys.internalKey, [
    { method: 'POST', path: /^\/internal\/engagement\/merges\/prepare$/, reply: () => ({ body: { sourceVoters: 2, targetVoters: 2, sharedVoters: 1, votesAfterMerge: 3, sourceComments: 1 } }) },
    {
      method: 'POST',
      path: /^\/internal\/engagement\/merges\/complete$/,
      reply: () => (behave.engagementComplete === 'fail'
        ? { status: 500, body: { error: { code: 'INTERNAL_ERROR', message: 'engagement database error' } } }
        : { body: { voteCount: 3, commentCount: 2 } })
    },
    { method: 'POST', path: /^\/internal\/engagement\/merges\/abort$/, reply: () => ({ body: { aborted: true } }) },
    { method: 'POST', path: /^\/internal\/engagement\/merges\/undo$/, reply: () => ({ body: { target: { voteCount: 2, commentCount: 1 }, source: { voteCount: 2, commentCount: 1 } } }) }
  ]);
  svc = await startService({
    port: 4535,
    env: { ROADMAP_URL: roadmap.url, ENGAGEMENT_URL: engagement.url, TURNSTILE_ENABLED: 'false', RATE_LIMITS: 'off', EVENTS: 'off' }
  });
  call = api(svc.url);
  u.admin = await newAdmin(call);
  for (const name of ['Erin', 'Dave']) u[name] = await newUser(call, name);
  f.A = feature('Dark mode for the dashboard');
  f.B = feature('Dashboard dark mode');
  f.C = feature('Export the board to CSV');
});
test.after(async () => {
  if (svc) await svc.stop();
  if (roadmap) await roadmap.stop();
  if (engagement) await engagement.stop();
});

test('only admins reach /api/admin', async () => {
  assert.equal((await call('GET', '/api/admin/users')).status, 401);
  assert.equal((await call('GET', '/api/admin/users', { token: u.Erin.token })).status, 403);
  assert.equal((await call('GET', '/api/admin/users', { token: u.admin.token })).status, 200);
  assert.equal((await merge(u.Erin, f.B, f.A)).status, 403);
});

test('moderation: suspend (read only), restore, ban (every session ends), never yourself', async () => {
  const s = await call('PATCH', `/api/admin/users/${u.Erin.id}/status`, { token: u.admin.token, body: { action: 'suspend', days: 1, reason: 'Spam test' } });
  assert.equal(s.status, 200, JSON.stringify(s.data));
  assert.equal(s.data.user.accountStatus, 'suspended');
  assert.equal((await call('GET', '/api/auth/me', { token: u.Erin.token })).status, 200, 'a suspended user can still read');
  const status = await call('GET', `/internal/identity/users/${u.Erin.id}/status`, { headers: { 'X-Service-Token': serviceToken(keys, { from: 'roadmap', to: 'admin', scope: 'identity:read' }) } });
  assert.equal(status.data.accountStatus, 'suspended', 'the other services see the suspension at once');
  assert.equal((await call('PATCH', `/api/admin/users/${u.Erin.id}/status`, { token: u.admin.token, body: { action: 'restore' } })).status, 200);
  assert.equal((await call('PATCH', `/api/admin/users/${u.Erin.id}/status`, { token: u.admin.token, body: { action: 'restore' } })).status, 409, 'already active');
  assert.equal((await call('PATCH', `/api/admin/users/${u.admin.id}/status`, { token: u.admin.token, body: { action: 'ban', reason: 'myself' } })).status, 403);
  assert.equal((await call('PATCH', `/api/admin/users/${u.Dave.id}/status`, { token: u.admin.token, body: { action: 'delete' } })).status, 400);

  const ban = await call('PATCH', `/api/admin/users/${u.Dave.id}/status`, { token: u.admin.token, body: { action: 'ban', reason: 'Abuse test' } });
  assert.equal(ban.status, 200);
  assert.ok([401, 403].includes((await call('GET', '/api/auth/me', { token: u.Dave.token })).status), 'old token stops working');
  assert.equal((await call('POST', '/api/auth/login', { body: { email: u.Dave.email, password: PASSWORD } })).status, 403);
  const audit = await call('GET', '/api/admin/audit', { token: u.admin.token });
  assert.equal(audit.status, 200);
  assert.ok(audit.data.items.some((e) => e.targetId === u.Dave.id), 'the ban is in the audit log');
});

test('duplicate suggestions come from the roadmap service over HTTP', async () => {
  roadmap.clear();
  const s = await call('GET', `/api/admin/features/${f.B}/duplicate-suggestions`, { token: u.admin.token });
  assert.equal(s.status, 200, JSON.stringify(s.data));
  const ids = s.data.suggestions.map((x) => x.featureId);
  assert.equal(ids[0], f.A, 'the similar request is first');
  assert.ok(!ids.includes(f.B), 'never the request itself');
  assert.ok(!ids.includes(f.C), 'an unrelated request is not suggested');
  assert.ok(roadmap.calls.every((c) => c.token.iss === 'admin' && c.token.scope.includes('features:read')));
  assert.equal((await call('GET', `/api/admin/features/${randomUUID()}/duplicate-suggestions`, { token: u.admin.token })).status, 404);
});

test('merge saga: every step in order, one request id, merge id as Idempotency-Key', async () => {
  roadmap.clear();
  engagement.clear();
  assert.equal((await merge(u.admin, f.A, f.A)).status, 400, 'not into itself');
  const m = await merge(u.admin, f.B, f.A);
  assert.equal(m.status, 201, JSON.stringify(m.data));
  f.mergeId = m.data.merge.mergeId;
  assert.equal(m.data.merge.state, 'COMMITTED');
  assert.equal(m.data.merge.stats.votesAfterMerge, 3);
  assert.equal(m.data.merge.canUndo, true);
  const calls = sagaCalls();
  assert.deepEqual(calls.map((c) => c.step), ['roadmap.prepare', 'engagement.prepare', 'roadmap.complete', 'engagement.complete']);
  assert.ok(calls.every((c) => c.idempotencyKey === f.mergeId), 'Idempotency-Key = mergeId');
  assert.equal(new Set(calls.map((c) => c.requestId)).size, 1, 'one request id through every service');
  assert.ok(calls.every((c) => c.token.scope.includes(c.svc === 'roadmap' ? 'features:merge' : 'engagement:merge')));
  const list = await call('GET', '/api/admin/merges', { token: u.admin.token });
  assert.equal(list.data.items.find((x) => x.mergeId === f.mergeId).state, 'COMMITTED');
});

test('merge fails half-way (engagement error): finished steps are undone, merge recorded FAILED, 503', async () => {
  roadmap.clear();
  engagement.clear();
  behave.engagementComplete = 'fail';
  const m = await merge(u.admin, f.C, f.A);
  behave.engagementComplete = 'ok';
  assert.equal(m.status, 503, JSON.stringify(m.data));
  assert.ok(!JSON.stringify(m.data).includes('engagement database error'), 'the other service\'s error text is not shown');
  const steps = sagaCalls().map((c) => c.step);
  const afterFailure = steps.slice(steps.lastIndexOf('engagement.complete') + 1);
  assert.deepEqual(afterFailure, ['engagement.abort', 'roadmap.undo'], `compensation, newest step first (all calls: ${steps.join(', ')})`);
  const list = await call('GET', '/api/admin/merges', { token: u.admin.token });
  const failed = list.data.items.find((x) => x.sourceId === f.C);
  assert.equal(failed.state, 'FAILED');
});

test('merge refused by the roadmap service (409) is passed on and the lock is released', async () => {
  roadmap.clear();
  engagement.clear();
  behave.roadmapPrepare = 'conflict';
  const m = await merge(u.admin, f.C, f.B);
  behave.roadmapPrepare = 'ok';
  assert.equal(m.status, 409);
  assert.equal(m.data.error.code, 'MERGE_CONFLICT');
  assert.deepEqual(sagaCalls().map((c) => c.step), ['roadmap.prepare', 'roadmap.abort']);
  assert.equal(engagement.calls.length, 0, 'engagement was never touched');
});

test('undo within 7 days: engagement first, then roadmap; a second undo is refused', async () => {
  roadmap.clear();
  engagement.clear();
  const undo = await call('POST', `/api/admin/merges/${f.mergeId}/undo`, { token: u.admin.token });
  assert.equal(undo.status, 200, JSON.stringify(undo.data));
  assert.equal(undo.data.merge.state, 'UNDONE');
  assert.deepEqual(sagaCalls().map((c) => c.step), ['engagement.undo', 'roadmap.undo']);
  const again = await call('POST', `/api/admin/merges/${f.mergeId}/undo`, { token: u.admin.token });
  assert.equal(again.status, 409);
  assert.equal(again.data.error.code, 'ALREADY_UNDONE');
  assert.equal((await call('POST', `/api/admin/merges/${randomUUID()}/undo`, { token: u.admin.token })).status, 404);
});

test('security events: failed logins are counted per address', async () => {
  for (let i = 0; i < 3; i += 1) await call('POST', '/api/auth/login', { body: { email: u.Erin.email, password: 'Wrong-pass-123' } });
  const r = await call('GET', '/api/admin/security-events?minutes=5', { token: u.admin.token });
  assert.equal(r.status, 200);
  assert.ok(r.data.totalEvents >= 3, JSON.stringify(r.data));
  assert.ok(r.data.sources.some((s) => (s.byAction.LOGIN_FAILED || 0) >= 3));
});
