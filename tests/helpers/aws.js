// Test helper: AWS settings for the local emulator (Floci on your PC).
// The tests use the same tables and secrets as the running service, so run the setup scripts first.
const AWS_ENV = {
  AWS_REGION: 'us-east-1',
  AWS_ENDPOINT_URL: process.env.AWS_ENDPOINT_URL || 'http://127.0.0.1:4566',
  AWS_ACCESS_KEY_ID: 'test',
  AWS_SECRET_ACCESS_KEY: 'test'
};
Object.assign(process.env, AWS_ENV);

const {
  SecretsManagerClient, GetSecretValueCommand, CreateSecretCommand
} = require('@aws-sdk/client-secrets-manager');
const { DynamoDBClient, DescribeTableCommand } = require('@aws-sdk/client-dynamodb');

const secretsClient = new SecretsManagerClient({});

async function readSecret(name) {
  try {
    const out = await secretsClient.send(new GetSecretValueCommand({ SecretId: name }));
    return JSON.parse(out.SecretString);
  } catch (e) {
    if (e.name === 'ResourceNotFoundException') return null;
    throw e;
  }
}

// Reads a secret, and creates it with make() ONLY if it does not exist yet.
// It never overwrites, so running the tests never breaks the keys your running services use.
async function getOrCreateSecret(name, make) {
  const existing = await readSecret(name);
  if (existing) return existing;
  const value = make();
  await secretsClient.send(new CreateSecretCommand({ Name: name, SecretString: JSON.stringify(value) }));
  return value;
}

// Stops early with a clear message when the tables were not created yet.
async function requireTables(names) {
  const db = new DynamoDBClient({});
  for (const name of names) {
    try {
      await db.send(new DescribeTableCommand({ TableName: name }));
    } catch (e) {
      if (e.name === 'ResourceNotFoundException') {
        throw new Error(`Table ${name} does not exist. Start Floci and run "npm run setup:tables" first.`);
      }
      throw new Error(`Cannot reach the AWS emulator at ${AWS_ENV.AWS_ENDPOINT_URL} (${e.name}). Is Floci running?`);
    }
  }
}

module.exports = { AWS_ENV, readSecret, getOrCreateSecret, requireTables };
