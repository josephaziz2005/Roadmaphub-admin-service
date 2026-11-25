// Administration Service (S3), part 4: CloudWatch Logs shipping and security monitoring (/roadhub/admin).
// Verifies sensitive-field redaction, real log delivery to Floci CloudWatch Logs (REQUEST,
// LOGIN_FAILED, ACCESS_DENIED), zero password/token leakage in logs, and metric filter setup.
const test = require('node:test');
const assert = require('node:assert');
const { randomUUID } = require('crypto');
const {
  CloudWatchLogsClient,
  GetLogEventsCommand,
  DescribeMetricFiltersCommand
} = require('@aws-sdk/client-cloudwatch-logs');
const { requireTables } = require('./helpers/aws');
const { loadKeys } = require('./helpers/keys');
const { startService, sleep } = require('./helpers/service');
const { api, uniqueEmail } = require('./helpers/api');
const { newUser } = require('./helpers/users');
const { sanitizeValue } = require('../services/cloudwatchSink');

const LOG_GROUP = '/roadhub/admin';
const LOG_STREAM = 'admin-service';
const cw = new CloudWatchLogsClient({});

let svc; let call; let regularUser;

test.before(async () => {
  await requireTables(['roadhub-users', 'roadhub-merges', 'roadhub-audit']);
  await loadKeys();
  svc = await startService({
    port: 4539,
    env: {
      CLOUDWATCH_LOG_GROUP: LOG_GROUP,
      CLOUDWATCH_LOG_STREAM: LOG_STREAM,
      CLOUDWATCH_LOGS: 'on',
      TURNSTILE_ENABLED: 'false',
      RATE_LIMITS: 'off',
      EVENTS: 'off',
      ROADMAP_URL: 'http://127.0.0.1:9',
      ENGAGEMENT_URL: 'http://127.0.0.1:9'
    }
  });
  call = api(svc.url);
  regularUser = await newUser(call, 'CwTester');
});
test.after(async () => svc && svc.stop());

test('sanitizeValue redacts sensitive keys recursively without touching safe fields', () => {
  const input = {
    event: 'TEST',
    userId: 'u-1',
    password: 'my-secret-password',
    authorization: 'Bearer abc.def.ghi',
    nested: { apiKey: 'key-123', token: 'tok-999', ok: true }
  };
  const out = sanitizeValue(input);
  assert.equal(out.event, 'TEST');
  assert.equal(out.userId, 'u-1');
  assert.equal(out.password, '[REDACTED]');
  assert.equal(out.authorization, '[REDACTED]');
  assert.equal(out.nested.apiKey, '[REDACTED]');
  assert.equal(out.nested.token, '[REDACTED]');
  assert.equal(out.nested.ok, true);
});

test('security events (LOGIN_FAILED and ACCESS_DENIED) ship to Floci CloudWatch Logs with zero secrets', async () => {
  const secretPass = 'SuperSecretWrongPass98765!';
  const failReqId = `cw-fail-${randomUUID().slice(0, 12)}`;
  const denyReqId = `cw-deny-${randomUUID().slice(0, 12)}`;

  // 1. Trigger a failed login (401 -> SECURITY LOGIN_FAILED)
  const badLogin = await call('POST', '/api/auth/login', {
    headers: { 'X-Request-Id': failReqId },
    body: { email: uniqueEmail('cw-nobody'), password: secretPass }
  });
  assert.equal(badLogin.status, 401);

  // 2. Trigger an unauthorized role attempt (403 -> SECURITY ACCESS_DENIED)
  const forbidden = await call('GET', '/api/admin/users', {
    token: regularUser.token,
    headers: { 'X-Request-Id': denyReqId }
  });
  assert.equal(forbidden.status, 403);

  // Poll CloudWatch Logs for flushed events (batch timer runs every 250 ms).
  let events = [];
  for (let i = 0; i < 15; i += 1) {
    const out = await cw.send(new GetLogEventsCommand({
      logGroupName: LOG_GROUP,
      logStreamName: LOG_STREAM,
      startFromHead: false,
      limit: 100
    }));
    events = (out.events || []).map((e) => e.message);
    const hasFail = events.some((m) => m.includes(failReqId) && m.includes('"event":"LOGIN_FAILED"'));
    const hasDeny = events.some((m) => m.includes(denyReqId) && m.includes('"event":"ACCESS_DENIED"'));
    if (hasFail && hasDeny) break;
    await sleep(250);
  }

  const failLine = events.find((m) => m.includes(failReqId) && m.includes('"event":"LOGIN_FAILED"'));
  const denyLine = events.find((m) => m.includes(denyReqId) && m.includes('"event":"ACCESS_DENIED"'));
  assert.ok(failLine, `Expected LOGIN_FAILED for ${failReqId} in CloudWatch Logs`);
  assert.ok(denyLine, `Expected ACCESS_DENIED for ${denyReqId} in CloudWatch Logs`);

  // Verify the parsed JSON structure and guarantee zero password or JWT leakage.
  const parsedFail = JSON.parse(failLine);
  const parsedDeny = JSON.parse(denyLine);
  assert.equal(parsedFail.level, 'SECURITY');
  assert.equal(parsedFail.service, 'admin');
  assert.equal(parsedDeny.level, 'SECURITY');
  assert.equal(parsedDeny.code, 'FORBIDDEN');

  const allText = events.join('\n');
  assert.ok(!allText.includes(secretPass), 'password must never appear in CloudWatch Logs');
  assert.ok(!allText.includes(regularUser.token), 'user JWT must never appear in CloudWatch Logs');
});

test('CloudWatch metric filters are configured on /roadhub/admin', async () => {
  const out = await cw.send(new DescribeMetricFiltersCommand({ logGroupName: LOG_GROUP }));
  const names = (out.metricFilters || []).map((f) => f.filterName);
  assert.ok(names.includes('roadhub-admin-failed-logins'), `missing failed-logins filter; found: ${names.join(', ')}`);
  assert.ok(names.includes('roadhub-admin-access-denied'), `missing access-denied filter; found: ${names.join(', ')}`);
});
