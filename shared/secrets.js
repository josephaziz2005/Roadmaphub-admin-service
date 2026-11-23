// Reads JSON secrets from AWS Secrets Manager (Floci) once and keeps them in memory.
// The code only knows secret NAMES; the values never appear in code, Git or logs.
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

const client = new SecretsManagerClient({});
const cache = new Map();

async function getSecret(name) {
  if (!cache.has(name)) {
    const promise = client.send(new GetSecretValueCommand({ SecretId: name }))
      .then((out) => JSON.parse(out.SecretString));
    cache.set(name, promise);
    promise.catch(() => cache.delete(name)); // do not cache a failure
  }
  return cache.get(name);
}

module.exports = { getSecret };
