// Administration Service (S3) on its own, part 1: accounts, logins (RS256), lockout, logout and the
// account-state endpoint that the other two services call. No other service is needed for these.
// Run: npm test   (needs Floci on localhost:4566 and "npm run setup:tables" once)
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { requireTables } = require('./helpers/aws');
const { loadKeys, serviceToken } = require('./helpers/keys');
const { startService } = require('./helpers/service');
const { api, uniqueEmail } = require('./helpers/api');
const { PASSWORD } = require('./helpers/users');

let keys; let svc; let call;
test.before(async () => {
  await requireTables(['roadhub-users', 'roadhub-merges', 'roadhub-audit']);
  keys = await loadKeys();
  svc = await startService({ port: 4530, env: { TURNSTILE_ENABLED: 'false', RATE_LIMITS: 'off', EVENTS: 'off', ROADMAP_URL: 'http://127.0.0.1:9', ENGAGEMENT_URL: 'http://127.0.0.1:9' } });
  call = api(svc.url);
});
test.after(async () => svc && svc.stop());

const register = (name, email, password = PASSWORD, extra = {}) => call('POST', '/api/auth/register', { body: { name, email, password, ...extra } });

test('runs as its own process and answers /health', async () => {
  const r = await call('GET', '/health');
  assert.deepEqual([r.status, r.data.service], [200, 'admin']);
});

test('register creates a "user" and returns a login token (RS256, no password hash)', async () => {
  const r = await register('Alice', uniqueEmail('alice'));
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.user.role, 'user');
  assert.equal(r.data.user.passwordHash, undefined);
  const claims = jwt.decode(r.data.token, { complete: true });
  assert.equal(claims.header.alg, 'RS256');
  assert.deepEqual([claims.payload.iss, claims.payload.aud, claims.payload.typ], ['roadhub-admin', 'roadhub-api', 'user']);
});

test('mass assignment: registering with role=admin -> 400', async () => {
  const r = await register('Mallory', uniqueEmail('m'), PASSWORD, { role: 'admin' });
  assert.equal(r.status, 400);
  assert.equal(r.data.error.code, 'VALIDATION_ERROR');
});

test('weak password and duplicate e-mail are refused', async () => {
  assert.equal((await register('Bob', uniqueEmail('b'), 'short1')).status, 400);
  const email = uniqueEmail('dup');
  assert.equal((await register('Dup', email)).status, 201);
  const again = await register('Dup', email.toUpperCase());
  assert.equal(again.status, 409, 'e-mail is compared without case');
  assert.equal(again.data.error.code, 'EMAIL_TAKEN');
});

test('two sign-ups with the same e-mail at the same moment: only one wins', async () => {
  const email = uniqueEmail('race');
  const results = await Promise.all([1, 2, 3].map(() => register('Race', email)));
  assert.equal(results.filter((r) => r.status === 201).length, 1, results.map((r) => r.status).join(','));
});

test('login: same message for unknown e-mail and wrong password; 5 failures lock the account', async () => {
  const email = uniqueEmail('lock');
  await register('Lock', email);
  const unknown = await call('POST', '/api/auth/login', { body: { email: uniqueEmail('nobody'), password: PASSWORD } });
  const wrong = await call('POST', '/api/auth/login', { body: { email, password: 'Wrong-pass-123' } });
  assert.equal(unknown.status, 401);
  assert.equal(wrong.status, 401);
  assert.equal(unknown.data.error.message, wrong.data.error.message, 'no hint whether the e-mail exists');
  for (let i = 0; i < 4; i += 1) await call('POST', '/api/auth/login', { body: { email, password: 'Wrong-pass-123' } });
  const locked = await call('POST', '/api/auth/login', { body: { email, password: PASSWORD } });
  assert.equal(locked.status, 423);
});

test('me works with the token; forged tokens (other key, alg none) -> 401', async () => {
  const email = uniqueEmail('me');
  const reg = await register('Me', email);
  const me = await call('GET', '/api/auth/me', { token: reg.data.token });
  assert.equal(me.status, 200);
  assert.equal(me.data.user.email, email);
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const forged = jwt.sign({ typ: 'user', role: 'admin', tv: 0 }, privateKey, {
    algorithm: 'RS256', subject: reg.data.user.userId, issuer: 'roadhub-admin', audience: 'roadhub-api', expiresIn: 600
  });
  assert.equal((await call('GET', '/api/auth/me', { token: forged })).status, 401);
  const none = jwt.sign({ typ: 'user', role: 'admin', tv: 0, sub: reg.data.user.userId }, '', { algorithm: 'none' });
  assert.equal((await call('GET', '/api/auth/me', { token: none })).status, 401);
});

test('logout ends every session (old token -> 401)', async () => {
  const reg = await register('Out', uniqueEmail('out'));
  assert.equal((await call('POST', '/api/auth/logout', { token: reg.data.token })).status, 204);
  assert.equal((await call('GET', '/api/auth/me', { token: reg.data.token })).status, 401);
});

test('internal account-state endpoint: refuses users and wrong scopes, answers services', async () => {
  const reg = await register('Stat', uniqueEmail('stat'));
  const path = `/internal/identity/users/${reg.data.user.userId}/status`;
  assert.equal((await call('GET', path)).status, 401);
  assert.equal((await call('GET', path, { headers: { 'X-Service-Token': reg.data.token } })).status, 401, 'a user login is not a service token');
  const wrongScope = serviceToken(keys, { from: 'engagement', to: 'admin', scope: 'features:read' });
  assert.equal((await call('GET', path, { headers: { 'X-Service-Token': wrongScope } })).status, 403);
  const ok = await call('GET', path, { headers: { 'X-Service-Token': serviceToken(keys, { from: 'engagement', to: 'admin', scope: 'identity:read' }) } });
  assert.equal(ok.status, 200);
  assert.deepEqual(Object.keys(ok.data).sort(), ['accountStatus', 'role', 'tokenVersion', 'userId'], 'no e-mail, no password hash');
  // Contacts (for notification e-mails) need their own scope.
  const contactsPath = '/internal/identity/users/contacts';
  const noContacts = await call('POST', contactsPath, { body: { userIds: [reg.data.user.userId] }, headers: { 'X-Service-Token': serviceToken(keys, { from: 'engagement', to: 'admin', scope: 'identity:read' }) } });
  assert.equal(noContacts.status, 403);
  const contacts = await call('POST', contactsPath, { body: { userIds: [reg.data.user.userId] }, headers: { 'X-Service-Token': serviceToken(keys, { from: 'engagement', to: 'admin', scope: 'identity:contacts' }) } });
  assert.equal(contacts.status, 200);
  assert.equal(contacts.data.items[0].name, 'Stat');
});
