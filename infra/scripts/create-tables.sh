#!/usr/bin/env bash
# Creates the Administration Service's own DynamoDB tables (owner: Joseph). Safe to run again.
# Only this service reads or writes these tables; the others ask over HTTP (/internal/identity/*).
source "$(dirname "$0")/../lib.sh"
step "DynamoDB tables: admin-service"

# Holds user items (userId = uuid) and e-mail lock items (userId = "email#<address>") so an
# e-mail address can only be registered once, even with two sign-ups at the same moment.
make_table "$PREFIX-users" \
  --attribute-definitions AttributeName=userId,AttributeType=S AttributeName=listKey,AttributeType=S AttributeName=createdAt,AttributeType=S \
  --key-schema AttributeName=userId,KeyType=HASH \
  --global-secondary-indexes "[$(gsi list-index listKey createdAt)]"
make_table "$PREFIX-merges" \
  --attribute-definitions AttributeName=mergeId,AttributeType=S AttributeName=listKey,AttributeType=S AttributeName=createdAt,AttributeType=S \
  --key-schema AttributeName=mergeId,KeyType=HASH \
  --global-secondary-indexes "[$(gsi list-index listKey createdAt)]"
make_table "$PREFIX-audit" \
  --attribute-definitions AttributeName=auditId,AttributeType=S AttributeName=listKey,AttributeType=S AttributeName=createdAt,AttributeType=S \
  --key-schema AttributeName=auditId,KeyType=HASH \
  --global-secondary-indexes "[$(gsi list-index listKey createdAt)]"

step "Extra settings"
for t in users merges audit; do point_in_time_recovery "$PREFIX-$t"; done
