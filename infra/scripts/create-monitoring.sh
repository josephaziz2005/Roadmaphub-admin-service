#!/usr/bin/env bash
# Creates CloudWatch Logs monitoring for the Administration Service (owner: Joseph, S3):
#   - Log group:     /roadhub/admin  (14-day retention)
#   - Log stream:    admin-service
#   - Metric filters: failed logins (FailedLoginCount) and access denied (AccessDeniedCount)
#   - CloudWatch alarm: roadhub-admin-brute-force-alarm -> SNS roadhub-ops-alerts
# Safe to run again.
source "$(dirname "$0")/../lib.sh"

LOG_GROUP="${CLOUDWATCH_LOG_GROUP:-/$PREFIX/admin}"
LOG_STREAM="${CLOUDWATCH_LOG_STREAM:-admin-service}"
NAMESPACE="RoadHub/Admin"
TOPIC_ARN="arn:aws:sns:${AWS_REGION}:${ACCOUNT_ID}:${PREFIX}-ops-alerts"

step "CloudWatch Logs: $LOG_GROUP"
if awsl logs create-log-group --log-group-name "$LOG_GROUP" >/dev/null 2>&1; then
  ok "log group $LOG_GROUP created"
else
  ok "log group $LOG_GROUP (already exists)"
fi

if awsl logs create-log-stream --log-group-name "$LOG_GROUP" --log-stream-name "$LOG_STREAM" >/dev/null 2>&1; then
  ok "log stream $LOG_STREAM created"
else
  ok "log stream $LOG_STREAM (already exists)"
fi

if awsl logs put-retention-policy --log-group-name "$LOG_GROUP" --retention-in-days 14 >/dev/null 2>&1; then
  ok "retention policy set to 14 days"
else
  info "retention policy not supported on this emulator"
fi

step "CloudWatch Metric Filters: $NAMESPACE"
if awsl logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "$PREFIX-admin-failed-logins" \
  --filter-pattern '{ $.level = "SECURITY" && $.event = "LOGIN_FAILED" }' \
  --metric-transformations "metricName=FailedLoginCount,metricNamespace=$NAMESPACE,metricValue=1" >/dev/null 2>&1; then
  ok "metric filter $PREFIX-admin-failed-logins (LOGIN_FAILED -> FailedLoginCount)"
else
  info "metric filter $PREFIX-admin-failed-logins not supported on this emulator"
fi

if awsl logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "$PREFIX-admin-access-denied" \
  --filter-pattern '{ $.level = "SECURITY" && ($.event = "ACCESS_DENIED" || $.event = "AUTH_FAILED") }' \
  --metric-transformations "metricName=AccessDeniedCount,metricNamespace=$NAMESPACE,metricValue=1" >/dev/null 2>&1; then
  ok "metric filter $PREFIX-admin-access-denied (ACCESS_DENIED/AUTH_FAILED -> AccessDeniedCount)"
else
  info "metric filter $PREFIX-admin-access-denied not supported on this emulator"
fi

step "CloudWatch Alarm -> SNS ($PREFIX-ops-alerts)"
if awsl cloudwatch put-metric-alarm \
  --alarm-name "$PREFIX-admin-brute-force-alarm" \
  --alarm-description "Triggers when 5 or more failed logins occur within 5 minutes on roadhub-admin-service" \
  --metric-name FailedLoginCount \
  --namespace "$NAMESPACE" \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --treat-missing-data notBreaching \
  --alarm-actions "$TOPIC_ARN" >/dev/null 2>&1; then
  ok "alarm $PREFIX-admin-brute-force-alarm -> $TOPIC_ARN"
else
  info "cloudwatch put-metric-alarm not supported on this emulator"
fi
