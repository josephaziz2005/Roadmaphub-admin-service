// Users in DynamoDB (table roadhub-users).
// Two kinds of items share the table:
//   { userId: <uuid>, listKey: 'USER', ... }            the account
//   { userId: 'email#<address>', ownerId: <uuid> }        e-mail lock: makes the address unique
const { randomUUID } = require('crypto');
const { GetCommand, UpdateCommand, TransactWriteCommand, BatchGetCommand, QueryCommand } = require('@aws-sdk/lib-dynamodb');
const { dynamo } = require('../../shared');
const config = require('../../config');

const { db, isConditionFailure } = dynamo;
const TABLE = config.tables.users;
const emailKey = (email) => `email#${email.toLowerCase()}`;

// Returns the new user, or null when the e-mail address is already registered.
async function createUser({ name, email, passwordHash, role = 'user' }) {
  const now = new Date().toISOString();
  const user = {
    userId: randomUUID(), listKey: 'USER', name, email: email.toLowerCase(), passwordHash, role,
    accountStatus: 'active', tokenVersion: 0, failedLoginCount: 0, createdAt: now, updatedAt: now
  };
  try {
    // Both items or neither: two sign-ups with the same address at the same moment cannot both win.
    await db.send(new TransactWriteCommand({
      TransactItems: [
        { Put: { TableName: TABLE, Item: { userId: emailKey(email), ownerId: user.userId, createdAt: now }, ConditionExpression: 'attribute_not_exists(userId)' } },
        { Put: { TableName: TABLE, Item: user, ConditionExpression: 'attribute_not_exists(userId)' } }
      ]
    }));
  } catch (e) {
    if (isConditionFailure(e)) return null;
    throw e;
  }
  return user;
}

async function findById(userId) {
  const out = await db.send(new GetCommand({ TableName: TABLE, Key: { userId }, ConsistentRead: true }));
  return out.Item && out.Item.listKey === 'USER' ? out.Item : null;
}

async function findByEmail(email) {
  const lock = await db.send(new GetCommand({ TableName: TABLE, Key: { userId: emailKey(email) }, ConsistentRead: true }));
  return lock.Item ? findById(lock.Item.ownerId) : null;
}

// Adds one failed attempt; returns the new count.
async function recordFailedLogin(userId) {
  const out = await db.send(new UpdateCommand({
    TableName: TABLE, Key: { userId },
    UpdateExpression: 'ADD failedLoginCount :one SET updatedAt = :now',
    ExpressionAttributeValues: { ':one': 1, ':now': new Date().toISOString() },
    ReturnValues: 'UPDATED_NEW'
  }));
  return out.Attributes.failedLoginCount;
}

async function lockAccount(userId, lockedUntil) {
  await db.send(new UpdateCommand({
    TableName: TABLE, Key: { userId },
    UpdateExpression: 'SET lockedUntil = :until, failedLoginCount = :zero',
    ExpressionAttributeValues: { ':until': lockedUntil, ':zero': 0 }
  }));
}

async function recordSuccessfulLogin(userId) {
  await db.send(new UpdateCommand({
    TableName: TABLE, Key: { userId },
    UpdateExpression: 'SET failedLoginCount = :zero, lastLoginAt = :now REMOVE lockedUntil',
    ExpressionAttributeValues: { ':zero': 0, ':now': new Date().toISOString() }
  }));
}

// Every token carries the version it was issued with; adding 1 ends all existing sessions.
async function bumpTokenVersion(userId) {
  const out = await db.send(new UpdateCommand({
    TableName: TABLE, Key: { userId },
    UpdateExpression: 'ADD tokenVersion :one SET updatedAt = :now',
    ExpressionAttributeValues: { ':one': 1, ':now': new Date().toISOString() },
    ReturnValues: 'UPDATED_NEW'
  }));
  return out.Attributes.tokenVersion;
}

async function setRole(userId, role) {
  await db.send(new UpdateCommand({
    TableName: TABLE, Key: { userId },
    UpdateExpression: 'SET #r = :role, updatedAt = :now ADD tokenVersion :one',
    ExpressionAttributeNames: { '#r': 'role' },
    ExpressionAttributeValues: { ':role': role, ':now': new Date().toISOString(), ':one': 1 }
  }));
}

// accountStatus: active | suspended | banned
async function setAccountStatus(userId, { accountStatus, suspendedUntil, reason, actorId, endSessions }) {
  const now = new Date().toISOString();
  const names = { '#s': 'accountStatus' };
  const values = { ':s': accountStatus, ':now': now, ':actor': actorId, ':user': 'USER' };
  let expression = 'SET #s = :s, updatedAt = :now, moderatedBy = :actor, moderatedAt = :now';
  if (suspendedUntil) { expression += ', suspendedUntil = :until'; values[':until'] = suspendedUntil; }
  if (reason) { expression += ', moderationReason = :reason'; values[':reason'] = reason; }
  const removes = [];
  if (!suspendedUntil) removes.push('suspendedUntil');
  if (!reason) removes.push('moderationReason');
  if (removes.length) expression += ` REMOVE ${removes.join(', ')}`;
  if (endSessions) { expression += ' ADD tokenVersion :one'; values[':one'] = 1; }
  const out = await db.send(new UpdateCommand({
    TableName: TABLE, Key: { userId }, UpdateExpression: expression,
    ConditionExpression: 'listKey = :user', ExpressionAttributeNames: names, ExpressionAttributeValues: values,
    ReturnValues: 'ALL_NEW'
  }));
  return out.Attributes;
}

async function findMany(userIds) {
  const unique = [...new Set(userIds)].slice(0, 100);
  if (!unique.length) return [];
  const out = await db.send(new BatchGetCommand({ RequestItems: { [TABLE]: { Keys: unique.map((userId) => ({ userId })) } } }));
  return (out.Responses[TABLE] || []).filter((u) => u.listKey === 'USER');
}

// Newest accounts first (list-index), one page at a time.
async function listUsers({ limit = 50, cursor } = {}) {
  const out = await db.send(new QueryCommand({
    TableName: TABLE, IndexName: 'list-index',
    KeyConditionExpression: 'listKey = :user', ExpressionAttributeValues: { ':user': 'USER' },
    ScanIndexForward: false, Limit: limit, ExclusiveStartKey: cursor
  }));
  return { items: out.Items || [], next: out.LastEvaluatedKey };
}

module.exports = {
  createUser, findById, findByEmail, recordFailedLogin, lockAccount, recordSuccessfulLogin,
  bumpTokenVersion, setRole, setAccountStatus, findMany, listUsers
};
