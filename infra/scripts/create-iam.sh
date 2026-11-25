#!/usr/bin/env bash
# Creates the least-privilege IAM role and inline policy for roadhub-admin-service (owner: Joseph, S3).
# Zero "Resource": "*" and zero access to other services' DynamoDB tables or Secrets Manager secrets.
# Note: Floci stores IAM roles and policies for verification and AWS parity, but does not enforce
# IAM evaluation locally; on real AWS these exact ARNs enforce strict service boundaries.
# Safe to run again.
source "$(dirname "$0")/../lib.sh"

ROLE_NAME="$PREFIX-admin-role"
POLICY_NAME="$PREFIX-admin-least-privilege"

TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ecs-tasks.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}'

INLINE_POLICY="{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Sid\": \"AdminDynamoDbAccess\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"dynamodb:GetItem\",
        \"dynamodb:PutItem\",
        \"dynamodb:UpdateItem\",
        \"dynamodb:Query\",
        \"dynamodb:BatchGetItem\"
      ],
      \"Resource\": [
        \"arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/${PREFIX}-users\",
        \"arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/${PREFIX}-users/index/list-index\",
        \"arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/${PREFIX}-merges\",
        \"arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/${PREFIX}-merges/index/list-index\",
        \"arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/${PREFIX}-audit\",
        \"arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/${PREFIX}-audit/index/list-index\"
      ]
    },
    {
      \"Sid\": \"AdminSecretsReadAccess\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"secretsmanager:GetSecretValue\"
      ],
      \"Resource\": [
        \"arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${PREFIX}/jwt-private*\",
        \"arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${PREFIX}/jwt-public*\",
        \"arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${PREFIX}/internal*\",
        \"arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${PREFIX}/turnstile*\"
      ]
    },
    {
      \"Sid\": \"AdminEventBridgePublish\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"events:PutEvents\"
      ],
      \"Resource\": \"arn:aws:events:${AWS_REGION}:${ACCOUNT_ID}:event-bus/${PREFIX}-events\"
    },
    {
      \"Sid\": \"AdminSnsConfirmSubscription\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"sns:ConfirmSubscription\"
      ],
      \"Resource\": \"arn:aws:sns:${AWS_REGION}:${ACCOUNT_ID}:${PREFIX}-ops-alerts\"
    },
    {
      \"Sid\": \"AdminCloudWatchLogsAccess\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"logs:CreateLogGroup\",
        \"logs:CreateLogStream\",
        \"logs:DescribeLogStreams\",
        \"logs:PutLogEvents\"
      ],
      \"Resource\": \"arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:/${PREFIX}/admin:*\"
    }
  ]
}"

step "IAM role: $ROLE_NAME"
if awsl iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  ok "role $ROLE_NAME (already exists)"
else
  if awsl iam create-role \
    --role-name "$ROLE_NAME" \
    --description "Least-privilege task role for RoadmapHub Administration Service (S3)" \
    --assume-role-policy-document "$TRUST_POLICY" >/dev/null; then
    ok "role $ROLE_NAME created"
  else
    fail "could not create IAM role $ROLE_NAME (is Floci running?)"
    exit 1
  fi
fi

step "IAM inline policy: $POLICY_NAME (zero wildcards)"
if awsl iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$POLICY_NAME" \
  --policy-document "$INLINE_POLICY" >/dev/null; then
  ok "policy $POLICY_NAME attached to $ROLE_NAME"
else
  fail "could not attach inline policy $POLICY_NAME"
  exit 1
fi
