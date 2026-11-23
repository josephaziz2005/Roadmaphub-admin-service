// Merge records (table roadhub-merges). State: PREPARING -> COMMITTED -> UNDOING -> UNDONE,
// or PREPARING -> FAILED. Every change is conditional on the state it expects.
const { PutCommand, GetCommand, UpdateCommand, QueryCommand } = require('@aws-sdk/lib-dynamodb');
const { dynamo } = require('../../shared');
const config = require('../../config');

const { db, isConditionFailure } = dynamo;
const TABLE = config.tables.merges;

async function create(record) {
  await db.send(new PutCommand({ TableName: TABLE, Item: { ...record, listKey: 'MERGE' }, ConditionExpression: 'attribute_not_exists(mergeId)' }));
  return record;
}

async function get(mergeId) {
  const out = await db.send(new GetCommand({ TableName: TABLE, Key: { mergeId }, ConsistentRead: true }));
  return out.Item || null;
}

// Moves the record from one of `fromStates` to a new state and saves extra fields. Returns null if the state was different.
async function transition(mergeId, fromStates, toState, fields = {}) {
  const names = { '#st': 'state' };
  const values = { ':to': toState, ':now': new Date().toISOString() };
  const sets = ['#st = :to', 'updatedAt = :now'];
  Object.entries(fields).forEach(([k, val], i) => { names[`#f${i}`] = k; values[`:f${i}`] = val; sets.push(`#f${i} = :f${i}`); });
  const allowed = fromStates.map((s, i) => { values[`:from${i}`] = s; return `#st = :from${i}`; });
  try {
    const out = await db.send(new UpdateCommand({
      TableName: TABLE, Key: { mergeId }, UpdateExpression: `SET ${sets.join(', ')}`,
      ConditionExpression: `(${allowed.join(' OR ')})`, ExpressionAttributeNames: names, ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW'
    }));
    return out.Attributes;
  } catch (e) {
    if (isConditionFailure(e)) return null;
    throw e;
  }
}

async function list({ limit = 50, cursor } = {}) {
  const out = await db.send(new QueryCommand({
    TableName: TABLE, IndexName: 'list-index', KeyConditionExpression: 'listKey = :m',
    ExpressionAttributeValues: { ':m': 'MERGE' }, ScanIndexForward: false, Limit: limit, ExclusiveStartKey: cursor
  }));
  return { items: out.Items || [], next: out.LastEvaluatedKey };
}

module.exports = { create, get, transition, list };
