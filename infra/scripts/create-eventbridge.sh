#!/usr/bin/env bash
# Creates the EventBridge custom event bus (roadhub-events), the shared events audit log group
# (/roadhub/events), and the admin-service audit rule matching FeatureMerged, MergeUndone,
# UserSuspended, UserBanned, and UserRestored. Safe to run again.
# Owner: Joseph (S3).
source "$(dirname "$0")/../lib.sh"

BUS_NAME="${EVENT_BUS_NAME:-$PREFIX-events}"
RULE_NAME="$PREFIX-admin-events-rule"
EVENTS_LOG_GROUP="/$PREFIX/events"
EVENTS_LOG_ARN="arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${EVENTS_LOG_GROUP}"

step "EventBridge bus: $BUS_NAME"
if awsl events create-event-bus --name "$BUS_NAME" >/dev/null 2>&1; then
  ok "event bus $BUS_NAME created"
else
  ok "event bus $BUS_NAME (already exists)"
fi

step "EventBridge audit target: $EVENTS_LOG_GROUP"
if awsl logs create-log-group --log-group-name "$EVENTS_LOG_GROUP" >/dev/null 2>&1; then
  ok "log group $EVENTS_LOG_GROUP created"
else
  ok "log group $EVENTS_LOG_GROUP (already exists)"
fi
awsl logs put-retention-policy --log-group-name "$EVENTS_LOG_GROUP" --retention-in-days 14 >/dev/null 2>&1 \
  && ok "retention policy set to 14 days" || info "retention policy skipped"

step "EventBridge rule: $RULE_NAME"
PATTERN='{"source":["roadhub.admin"],"detail-type":["FeatureMerged","MergeUndone","UserSuspended","UserBanned","UserRestored"]}'
if awsl events put-rule \
  --event-bus-name "$BUS_NAME" \
  --name "$RULE_NAME" \
  --description "Routes Administration Service domain events to CloudWatch Logs for auditability" \
  --event-pattern "$PATTERN" \
  --state ENABLED >/dev/null; then
  ok "rule $RULE_NAME enabled on $BUS_NAME"
else
  fail "could not create EventBridge rule $RULE_NAME"
  exit 1
fi

if awsl events put-targets \
  --event-bus-name "$BUS_NAME" \
  --rule "$RULE_NAME" \
  --targets "Id=admin-events-log-target,Arn=$EVENTS_LOG_ARN" >/dev/null; then
  ok "target $EVENTS_LOG_GROUP attached to $RULE_NAME"
else
  fail "could not attach target $EVENTS_LOG_GROUP to $RULE_NAME"
  exit 1
fi
