// Append-only audit log (table roadhub-audit): admin actions and security events.
const { randomUUID } = require('crypto');
const { PutCommand, QueryCommand } = require('@aws-sdk/lib-dynamodb');
const { dynamo, logger } = require('../../shared');
const config = require('../../config');

const { db } = dynamo;
const TABLE = config.tables.audit;

// type: ACTION (something an admin/user did) | SECURITY (failed login, lockout, ...)
async function record({ type = 'ACTION', action, actorId, targetType, targetId, details, ip, requestId }) {
  const item = {
    auditId: randomUUID(), listKey: 'AUDIT', createdAt: new Date().toISOString(),
    type, action, actorId, targetType, targetId, details, ip, requestId
  };
  try {
    await db.send(new PutCommand({ TableName: TABLE, Item: item, ConditionExpression: 'attribute_not_exists(auditId)' }));
  } catch (e) {
    // The audit write must never hide the real answer; it is still in the service log.
    logger.error('AUDIT_WRITE_FAILED', { action, name: e.name });
  }
  return item;
}

async function list({ limit = 100, cursor, type } = {}) {
  const params = {
    TableName: TABLE, IndexName: 'list-index', KeyConditionExpression: 'listKey = :a',
    ExpressionAttributeValues: { ':a': 'AUDIT' }, ScanIndexForward: false, Limit: limit, ExclusiveStartKey: cursor
  };
  if (type) {
    params.FilterExpression = '#t = :type';
    params.ExpressionAttributeNames = { '#t': 'type' };
    params.ExpressionAttributeValues[':type'] = type;
  }
  const out = await db.send(new QueryCommand(params));
  return { items: out.Items || [], next: out.LastEvaluatedKey };
}

module.exports = { record, list };
