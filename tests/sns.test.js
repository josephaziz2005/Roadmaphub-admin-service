// Administration Service (S3), part 3: SNS operational alert webhook (/internal/alerts/sns).
// Verifies TopicArn checks, signature metadata validation, text/plain SNS payloads, secret-key
// filtering, admin-only audit visibility (type=OPS_ALERT), and real Floci SNS topic delivery.
const test = require('node:test');
const assert = require('node:assert');
const { randomUUID } = require('crypto');
const { SNSClient, CreateTopicCommand, SubscribeCommand, PublishCommand, ListSubscriptionsByTopicCommand, UnsubscribeCommand } = require('@aws-sdk/client-sns');
const { requireTables } = require('./helpers/aws');
const { loadKeys } = require('./helpers/keys');
const { startService, sleep } = require('./helpers/service');
const { api } = require('./helpers/api');
const { newUser, newAdmin } = require('./helpers/users');

const TOPIC_ARN = 'arn:aws:sns:us-east-1:000000000000:roadhub-ops-alerts';
const VALID_SIG = {
  SignatureVersion: '1',
  Signature: 'dGVzdC1zaWduYXR1cmUtYmFzZTY0LXBsYWNlaG9sZGVy',
  SigningCertURL: 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem'
};

let svc; let call; let admin; let user;

async function postSns(rawBody, contentType = 'text/plain; charset=UTF-8') {
  const res = await fetch(`${svc.url}/internal/alerts/sns`, {
    method: 'POST',
    headers: { 'Content-Type': contentType },
    body: typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody)
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

test.before(async () => {
  await requireTables(['roadhub-users', 'roadhub-merges', 'roadhub-audit']);
  await loadKeys();
  svc = await startService({
    port: 4538,
    env: { TURNSTILE_ENABLED: 'false', RATE_LIMITS: 'off', EVENTS: 'off', ROADMAP_URL: 'http://127.0.0.1:9', ENGAGEMENT_URL: 'http://127.0.0.1:9' }
  });
  call = api(svc.url);
  admin = await newAdmin(call);
  user = await newUser(call, 'SnsTester');
});
test.after(async () => svc && svc.stop());

test('SNS webhook rejects malformed payloads and invalid message types (400)', async () => {
  assert.equal((await postSns('not-json-at-all')).status, 400);
  assert.equal((await postSns({ Type: 'Bogus', MessageId: randomUUID(), TopicArn: TOPIC_ARN, ...VALID_SIG })).status, 400);
  assert.equal((await postSns({ Type: 'Notification', MessageId: randomUUID(), TopicArn: TOPIC_ARN, ...VALID_SIG })).status, 400, 'Message required');
  assert.equal((await postSns({ Type: 'SubscriptionConfirmation', MessageId: randomUUID(), TopicArn: TOPIC_ARN, ...VALID_SIG })).status, 400, 'Token required');
});

test('SNS webhook rejects wrong TopicArn and spoofed signature metadata (403)', async () => {
  const wrongTopic = await postSns({
    Type: 'Notification', MessageId: randomUUID(),
    TopicArn: 'arn:aws:sns:us-east-1:000000000000:evil-topic',
    Message: 'spoofed', ...VALID_SIG
  });
  assert.equal(wrongTopic.status, 403);
  assert.equal(wrongTopic.data.error.code, 'SNS_TOPIC_MISMATCH');

  const wrongSub = await postSns({
    Type: 'SubscriptionConfirmation', MessageId: randomUUID(),
    TopicArn: 'arn:aws:sns:us-east-1:000000000000:evil-topic',
    Token: 'fake-token', ...VALID_SIG
  });
  assert.equal(wrongSub.status, 403);

  const badCert = await postSns({
    Type: 'Notification', MessageId: randomUUID(), TopicArn: TOPIC_ARN,
    Message: 'spoofed cert', SignatureVersion: '1',
    Signature: VALID_SIG.Signature, SigningCertURL: 'https://evil.example/cert.pem'
  });
  assert.equal(badCert.status, 403);
  assert.equal(badCert.data.error.code, 'SNS_CERT_URL_INVALID');

  const badVer = await postSns({
    Type: 'Notification', MessageId: randomUUID(), TopicArn: TOPIC_ARN,
    Message: 'bad version', SignatureVersion: '99',
    Signature: VALID_SIG.Signature, SigningCertURL: VALID_SIG.SigningCertURL
  });
  assert.equal(badVer.status, 403);
  assert.equal(badVer.data.error.code, 'SNS_SIGNATURE_INVALID');
});

test('valid text/plain SNS alarm is stored as OPS_ALERT and visible only to admins', async () => {
  const messageId = randomUUID();
  const r = await postSns({
    Type: 'Notification',
    MessageId: messageId,
    TopicArn: TOPIC_ARN,
    Subject: 'ALARM: "roadhub-failed-logins" in US East',
    Message: JSON.stringify({
      AlarmName: 'roadhub-failed-logins',
      NewStateValue: 'ALARM',
      NewStateReason: 'Threshold Crossed: 12 failed logins in 5 minutes',
      apiKey: 'should-never-be-stored'
    }),
    Timestamp: new Date().toISOString(),
    ...VALID_SIG
  }, 'text/plain; charset=UTF-8');

  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.status, 'received');
  assert.equal(r.data.messageId, messageId);

  // Regular users cannot read the audit / ops-alerts feed.
  assert.equal((await call('GET', '/api/admin/audit?type=OPS_ALERT', { token: user.token })).status, 403);

  // Admins see the parsed alert, with zero leaked secrets.
  const audit = await call('GET', '/api/admin/audit?type=OPS_ALERT', { token: admin.token });
  assert.equal(audit.status, 200);
  const entry = audit.data.items.find((e) => e.details && e.details.messageId === messageId);
  assert.ok(entry, 'OPS_ALERT should be recorded in roadhub-audit');
  assert.equal(entry.type, 'OPS_ALERT');
  assert.equal(entry.action, 'sns.ops_alert');
  assert.equal(entry.details.alarmName, 'roadhub-failed-logins');
  assert.equal(entry.details.newState, 'ALARM');
  assert.ok(!JSON.stringify(entry).includes('should-never-be-stored'), 'sensitive keys must never be stored');
});

test('sensitive keys inside generic JSON alerts are stripped before storing', async () => {
  const messageId = randomUUID();
  const r = await postSns({
    Type: 'Notification',
    MessageId: messageId,
    TopicArn: TOPIC_ARN,
    Subject: 'Worker failure',
    Message: JSON.stringify({ worker: 'notify', attempts: 3, secretToken: 'leaked-value', password: 'pw' }),
    ...VALID_SIG
  }, 'application/json');

  assert.equal(r.status, 200);
  const audit = await call('GET', '/api/admin/audit?type=OPS_ALERT', { token: admin.token });
  const entry = audit.data.items.find((e) => e.details && e.details.messageId === messageId);
  assert.ok(entry);
  assert.equal(entry.details.worker, 'notify');
  assert.equal(entry.details.attempts, 3);
  assert.equal(entry.details.secretToken, undefined);
  assert.equal(entry.details.password, undefined);
});

test('Floci SNS end-to-end: create topic, subscribe admin webhook, and publish alert', async () => {
  const sns = new SNSClient({});
  const topic = await sns.send(new CreateTopicCommand({ Name: 'roadhub-ops-alerts' }));
  assert.equal(topic.TopicArn, TOPIC_ARN);

  await sns.send(new SubscribeCommand({
    TopicArn: TOPIC_ARN,
    Protocol: 'http',
    Endpoint: 'http://host.docker.internal:4538/internal/alerts/sns'
  }));
  await sleep(400);

  const tag = `floci-sns-e2e-${randomUUID().slice(0, 8)}`;
  const pub = await sns.send(new PublishCommand({
    TopicArn: TOPIC_ARN,
    Subject: 'Floci E2E Ops Alert',
    Message: JSON.stringify({ source: 'engagement-worker', reason: tag })
  }));
  assert.ok(pub.MessageId);

  // Poll briefly for asynchronous HTTP webhook delivery from Floci container to host :4538.
  let delivered = null;
  for (let i = 0; i < 15; i += 1) {
    const audit = await call('GET', '/api/admin/audit?type=OPS_ALERT', { token: admin.token });
    delivered = audit.data.items.find((e) => e.details && e.details.reason === tag);
    if (delivered) break;
    await sleep(200);
  }
  assert.ok(delivered, `Floci SNS did not deliver message ${pub.MessageId} to /internal/alerts/sns; logs:\n${svc.logs.slice(-10).join('\n')}`);
  assert.equal(delivered.details.source, 'engagement-worker');

  // Clean up the temporary test-port subscription so Floci keeps only real subscriptions.
  const subs = await sns.send(new ListSubscriptionsByTopicCommand({ TopicArn: TOPIC_ARN }));
  for (const s of subs.Subscriptions || []) {
    if (s.Endpoint === 'http://host.docker.internal:4538/internal/alerts/sns' && s.SubscriptionArn && s.SubscriptionArn.startsWith('arn:')) {
      await sns.send(new UnsubscribeCommand({ SubscriptionArn: s.SubscriptionArn }));
    }
  }
});
