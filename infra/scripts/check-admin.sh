#!/usr/bin/env bash
# Automated verification of all AWS/Floci resources owned by roadhub-admin-service (owner: Joseph, S3).
# Run: npm run check:aws  (or: bash infra/scripts/check-admin.sh)
source "$(dirname "$0")/../lib.sh"

PASS=0
FAIL=0

check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    ok "PASS  $label"
    PASS=$((PASS + 1))
  else
    fail "FAIL  $label"
    FAIL=$((FAIL + 1))
  fi
}

step "1. Floci connectivity"
check "Floci endpoint reachable ($AWS_ENDPOINT_URL)" awsl sts get-caller-identity

step "2. DynamoDB tables (admin-service only)"
for tbl in "$PREFIX-users" "$PREFIX-merges" "$PREFIX-audit"; do
  check "DynamoDB table $tbl" awsl dynamodb describe-table --table-name "$tbl"
done

step "3. Secrets Manager (admin-owned secrets)"
for sec in "$PREFIX/jwt-private" "$PREFIX/jwt-public" "$PREFIX/internal" "$PREFIX/turnstile"; do
  check "Secret $sec" awsl secretsmanager describe-secret --secret-id "$sec"
done

step "4. SNS operational alerts"
check "SNS topic $PREFIX-ops-alerts" awsl sns get-topic-attributes \
  --topic-arn "arn:aws:sns:${AWS_REGION}:${ACCOUNT_ID}:${PREFIX}-ops-alerts"

step "5. CloudWatch Logs, metric filters & brute-force alarm"
check "CloudWatch log group /$PREFIX/admin" bash -c "source '$ROOT_DIR/infra/lib.sh'; awsl logs describe-log-groups --log-group-name-prefix '/$PREFIX/admin' --query 'logGroups[?logGroupName==\`/$PREFIX/admin\`].logGroupName' --output text | grep -qx '/$PREFIX/admin'"
check "Metric filter $PREFIX-admin-failed-logins" bash -c "source '$ROOT_DIR/infra/lib.sh'; awsl logs describe-metric-filters --log-group-name '/$PREFIX/admin' --filter-name-prefix '$PREFIX-admin-failed-logins' --query 'metricFilters[0].filterName' --output text | grep -qx '$PREFIX-admin-failed-logins'"
check "Metric filter $PREFIX-admin-access-denied" bash -c "source '$ROOT_DIR/infra/lib.sh'; awsl logs describe-metric-filters --log-group-name '/$PREFIX/admin' --filter-name-prefix '$PREFIX-admin-access-denied' --query 'metricFilters[0].filterName' --output text | grep -qx '$PREFIX-admin-access-denied'"
check "CloudWatch alarm $PREFIX-admin-brute-force-alarm" bash -c "source '$ROOT_DIR/infra/lib.sh'; awsl cloudwatch describe-alarms --alarm-names '$PREFIX-admin-brute-force-alarm' --query 'MetricAlarms[0].AlarmName' --output text | grep -qx '$PREFIX-admin-brute-force-alarm'"

step "6. EventBridge bus & admin audit rule"
check "EventBridge bus $PREFIX-events" awsl events describe-event-bus --name "$PREFIX-events"
check "EventBridge rule $PREFIX-admin-events-rule" awsl events describe-rule --event-bus-name "$PREFIX-events" --name "$PREFIX-admin-events-rule"

step "7. IAM least-privilege role & policy"
check "IAM role $PREFIX-admin-role" awsl iam get-role --role-name "$PREFIX-admin-role"
POLICY_JSON="$(awsl iam get-role-policy --role-name "$PREFIX-admin-role" --policy-name "$PREFIX-admin-least-privilege" --output json 2>/dev/null || true)"
if [ -n "$POLICY_JSON" ] && ! printf '%s' "$POLICY_JSON" | grep -q '"Resource": "\*"'; then
  ok "PASS  IAM policy $PREFIX-admin-least-privilege exists with zero Resource:*"
  PASS=$((PASS + 1))
else
  fail "FAIL  IAM policy $PREFIX-admin-least-privilege missing or contains Resource:*"
  FAIL=$((FAIL + 1))
fi
if [ -n "$POLICY_JSON" ] && ! printf '%s' "$POLICY_JSON" | grep -qE 'roadhub-features|roadhub-votes|roadhub-comments|roadhub/resend'; then
  ok "PASS  IAM policy excludes other services' tables and roadhub/resend"
  PASS=$((PASS + 1))
else
  fail "FAIL  IAM policy references another service's resources"
  FAIL=$((FAIL + 1))
fi

echo
printf 'Result: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
