// Administration Service (S3), part 6: IAM least-privilege role & policy verification on Floci.
// Verifies roadhub-admin-role and roadhub-admin-least-privilege enforce strict service boundaries:
// zero wildcard actions/resources, only admin-owned tables & secrets, no DeleteItem/Scan, and
// zero access to roadmap/engagement tables or roadhub/resend.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const { AWS_ENV } = require('./helpers/aws');

function awsJson(args) {
  const out = execFileSync('aws', ['--endpoint-url', AWS_ENV.AWS_ENDPOINT_URL, '--region', AWS_ENV.AWS_REGION, ...args, '--output', 'json'], {
    env: { ...process.env, ...AWS_ENV, AWS_PAGER: '', MSYS_NO_PATHCONV: '1' },
    encoding: 'utf8'
  });
  return JSON.parse(out);
}

test('IAM role roadhub-admin-role exists and trusts only ecs-tasks.amazonaws.com', () => {
  const { Role } = awsJson(['iam', 'get-role', '--role-name', 'roadhub-admin-role']);
  assert.equal(Role.RoleName, 'roadhub-admin-role');
  const trust = typeof Role.AssumeRolePolicyDocument === 'string'
    ? JSON.parse(decodeURIComponent(Role.AssumeRolePolicyDocument))
    : Role.AssumeRolePolicyDocument;
  assert.equal(trust.Statement.length, 1);
  assert.equal(trust.Statement[0].Principal.Service, 'ecs-tasks.amazonaws.com');
  assert.equal(trust.Statement[0].Action, 'sts:AssumeRole');
});

test('IAM policy roadhub-admin-least-privilege has zero wildcards and strict service boundaries', () => {
  const res = awsJson(['iam', 'get-role-policy', '--role-name', 'roadhub-admin-role', '--policy-name', 'roadhub-admin-least-privilege']);
  const doc = typeof res.PolicyDocument === 'string'
    ? JSON.parse(decodeURIComponent(res.PolicyDocument))
    : res.PolicyDocument;

  assert.equal(doc.Statement.length, 5);

  const allActions = doc.Statement.flatMap((s) => [].concat(s.Action));
  const allResources = doc.Statement.flatMap((s) => [].concat(s.Resource));

  // Zero bare wildcard actions or resources
  assert.ok(allActions.every((a) => a !== '*' && !a.endsWith(':*')), `wildcard action found: ${allActions.join(', ')}`);
  assert.ok(allResources.every((r) => r !== '*'), `bare Resource:* found: ${allResources.join(', ')}`);

  // No destructive or full-table-scan DynamoDB actions
  for (const forbidden of ['dynamodb:Scan', 'dynamodb:DeleteItem', 'dynamodb:DeleteTable', 'secretsmanager:PutSecretValue', 'secretsmanager:DeleteSecret']) {
    assert.ok(!allActions.includes(forbidden), `unexpected privileged action: ${forbidden}`);
  }

  // Only admin-owned resources — never roadmap/engagement tables or Resend secret
  const joined = allResources.join('\n');
  for (const required of ['table/roadhub-users', 'table/roadhub-merges', 'table/roadhub-audit', 'secret:roadhub/jwt-private*', 'secret:roadhub/jwt-public*', 'secret:roadhub/internal*', 'secret:roadhub/turnstile*', 'event-bus/roadhub-events', ':roadhub-ops-alerts', 'log-group:/roadhub/admin:*']) {
    assert.ok(joined.includes(required), `missing required resource ${required}`);
  }
  for (const foreign of ['roadhub-features', 'roadhub-categories', 'roadhub-votes', 'roadhub-comments', 'roadhub-notifications', 'roadhub/resend', '/roadhub/roadmap', '/roadhub/engagement']) {
    assert.ok(!joined.includes(foreign), `policy must not grant access to foreign resource ${foreign}`);
  }
});
