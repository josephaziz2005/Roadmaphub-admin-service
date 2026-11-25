#!/usr/bin/env bash
# Creates the operational alerts SNS topic (roadhub-ops-alerts) and subscribes the
# Administration Service's internal webhook (/internal/alerts/sns). Safe to run again.
# Owner: Joseph (S3).
source "$(dirname "$0")/../lib.sh"

TOPIC_NAME="${OPS_TOPIC_NAME:-$PREFIX-ops-alerts}"
ENDPOINT="${SNS_ALERT_ENDPOINT:-http://host.docker.internal:3003/internal/alerts/sns}"

step "SNS: $TOPIC_NAME"
TOPIC_ARN="$(awsl sns create-topic --name "$TOPIC_NAME" --query TopicArn --output text)"
if [ -z "$TOPIC_ARN" ]; then
  fail "could not create SNS topic $TOPIC_NAME (is Floci running?)"
  exit 1
fi
ok "topic $TOPIC_ARN"

# Floci runs inside Docker, so host.docker.internal reaches the admin service on your PC (:3003).
# If admin-service is not running yet, SNS subscription confirmation stays pending; re-run this
# script once "npm start" is up so Floci confirms the subscription automatically.
if awsl sns subscribe \
  --topic-arn "$TOPIC_ARN" \
  --protocol http \
  --notification-endpoint "$ENDPOINT" >/dev/null 2>&1; then
  ok "subscribed $ENDPOINT"
else
  info "subscribe failed or $ENDPOINT not reachable yet — start admin-service (npm start) and re-run create-sns.sh"
fi
