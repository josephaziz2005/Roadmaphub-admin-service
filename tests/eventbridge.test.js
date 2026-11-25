// Administration Service (S3), part 5: EventBridge domain event publishing (roadhub-events).
// Verifies the event bus, rule, and /roadhub/events CloudWatch target exist on Floci, and proves
// live EventBridge pattern matching + delivery (via a temporary SQS target, since Floci routes
// EventBridge to SQS/SNS targets while storing CloudWatch Logs targets for AWS parity).
const test = require('node:test');
const assert = require('node:assert');
const { randomUUID } = require('crypto');
const {
  EventBridgeClient,
  DescribeEventBusCommand,
  DescribeRuleCommand,
  ListTargetsByRuleCommand,
  PutTargetsCommand,
  RemoveTargetsCommand
} = require('@aws-sdk/client-eventbridge');
const {
  SQSClient,
  CreateQueueCommand,
  GetQueueAttributesCommand,
  ReceiveMessageCommand,
  DeleteQueueCommand
} = require('@aws-sdk/client-sqs');
const { requireTables } = require('./helpers/aws');
const { loadKeys } = require('./helpers/keys');
const { startService, sleep } = require('./helpers/service');
const { api } = require('./helpers/api');
const { newUser, newAdmin } = require('./helpers/users');

const BUS_NAME = 'roadhub-events';
const RULE_NAME = 'roadhub-admin-events-rule';
const EVENTS_LOG_GROUP = '/roadhub/events';

const eb = new EventBridgeClient({});
const sqs = new SQSClient({ useQueueUrlAsEndpoint: false });

let svc; let call; let admin; let targetUser;

test.before(async () => {
  await requireTables(['roadhub-users', 'roadhub-merges', 'roadhub-audit']);
  await loadKeys();
  svc = await startService({
    port: 4540,
    env: {
      EVENTS: 'on',
      EVENT_BUS_NAME: BUS_NAME,
      CLOUDWATCH_LOGS: 'off',
      TURNSTILE_ENABLED: 'false',
      RATE_LIMITS: 'off',
      ROADMAP_URL: 'http://127.0.0.1:9',
      ENGAGEMENT_URL: 'http://127.0.0.1:9'
    }
  });
  call = api(svc.url);
  admin = await newAdmin(call);
  targetUser = await newUser(call, 'EbTester');
});
test.after(async () => svc && svc.stop());

test('EventBridge bus roadhub-events, admin audit rule, and /roadhub/events target exist', async () => {
  const bus = await eb.send(new DescribeEventBusCommand({ Name: BUS_NAME }));
  assert.equal(bus.Name, BUS_NAME);

  const rule = await eb.send(new DescribeRuleCommand({ EventBusName: BUS_NAME, Name: RULE_NAME }));
  assert.equal(rule.State, 'ENABLED');
  const pattern = JSON.parse(rule.EventPattern);
  assert.deepEqual(pattern.source, ['roadhub.admin']);
  assert.ok(pattern['detail-type'].includes('FeatureMerged'));
  assert.ok(pattern['detail-type'].includes('MergeUndone'));
  assert.ok(pattern['detail-type'].includes('UserSuspended'));
  assert.ok(pattern['detail-type'].includes('UserBanned'));
  assert.ok(pattern['detail-type'].includes('UserRestored'));

  const targets = await eb.send(new ListTargetsByRuleCommand({ EventBusName: BUS_NAME, Rule: RULE_NAME }));
  assert.ok(
    (targets.Targets || []).some((t) => t.Arn && t.Arn.endsWith(`:log-group:${EVENTS_LOG_GROUP}`)),
    `expected target ${EVENTS_LOG_GROUP}, got ${JSON.stringify(targets.Targets)}`
  );
});

test('moderation actions publish UserSuspended and UserRestored through EventBridge rule to target', async () => {
  const suffix = randomUUID().slice(0, 8);
  const targetId = `eb-test-sqs-${suffix}`;
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: `roadhub-admin-eb-verify-${suffix}` }));
  const { Attributes } = await sqs.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ['QueueArn'] }));

  try {
    await eb.send(new PutTargetsCommand({
      EventBusName: BUS_NAME,
      Rule: RULE_NAME,
      Targets: [{ Id: targetId, Arn: Attributes.QueueArn }]
    }));

    const suspendReqId = `eb-susp-${randomUUID().slice(0, 12)}`;
    const restoreReqId = `eb-rest-${randomUUID().slice(0, 12)}`;

    const s = await call('PATCH', `/api/admin/users/${targetUser.id}/status`, {
      token: admin.token,
      headers: { 'X-Request-Id': suspendReqId },
      body: { action: 'suspend', days: 2, reason: 'EventBridge test' }
    });
    assert.equal(s.status, 200, JSON.stringify(s.data));

    const r = await call('PATCH', `/api/admin/users/${targetUser.id}/status`, {
      token: admin.token,
      headers: { 'X-Request-Id': restoreReqId },
      body: { action: 'restore' }
    });
    assert.equal(r.status, 200, JSON.stringify(r.data));

    // Verify PutEvents succeeded with zero failures.
    await sleep(200);
    const published = svc.logs.filter((l) => l.includes('"event":"EVENT_PUBLISHED"'));
    assert.ok(published.some((l) => l.includes(suspendReqId) && l.includes('"eventType":"UserSuspended"')), 'UserSuspended should be published');
    assert.ok(published.some((l) => l.includes(restoreReqId) && l.includes('"eventType":"UserRestored"')), 'UserRestored should be published');
    assert.ok(!svc.logs.some((l) => l.includes('"event":"EVENT_PUBLISH_FAILED"')), 'no publish failures expected');

    // Verify Floci EventBridge matched our rule and delivered both events to the SQS target.
    const received = [];
    for (let i = 0; i < 10 && received.length < 2; i += 1) {
      const out = await sqs.send(new ReceiveMessageCommand({ QueueUrl, MaxNumberOfMessages: 10, WaitTimeSeconds: 0 }));
      for (const msg of out.Messages || []) received.push(JSON.parse(msg.Body));
      if (received.length < 2) await sleep(150);
    }

    const suspEvent = received.find((e) => e['detail-type'] === 'UserSuspended' && e.detail && e.detail.requestId === suspendReqId);
    const restEvent = received.find((e) => e['detail-type'] === 'UserRestored' && e.detail && e.detail.requestId === restoreReqId);
    assert.ok(suspEvent, `Expected UserSuspended in EventBridge SQS target; got: ${JSON.stringify(received)}`);
    assert.ok(restEvent, `Expected UserRestored in EventBridge SQS target; got: ${JSON.stringify(received)}`);
    assert.equal(suspEvent.source, 'roadhub.admin');
    assert.equal(suspEvent.detail.userId, targetUser.id);
    assert.equal(restEvent.detail.userId, targetUser.id);
  } finally {
    await eb.send(new RemoveTargetsCommand({ EventBusName: BUS_NAME, Rule: RULE_NAME, Ids: [targetId] })).catch(() => {});
    await sqs.send(new DeleteQueueCommand({ QueueUrl })).catch(() => {});
  }
});
