// One DynamoDB Document client per process. No keys in code: on a team PC the Floci
// settings come from .env (test keys), on AWS the task's IAM role would be used.
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient } = require('@aws-sdk/lib-dynamodb');

const db = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: { removeUndefinedValues: true }
});

// True when DynamoDB refused a write because a condition was false.
function isConditionFailure(err) {
  return err && (err.name === 'ConditionalCheckFailedException' || err.name === 'TransactionCanceledException');
}

module.exports = { db, isConditionFailure };
