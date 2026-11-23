// Test helper: the keys the services use, read from Secrets Manager (Floci).
// Normally the admin-service repo creates them (bash infra/scripts/create-secrets.sh).
// If they are missing (a fresh Floci), they are created here once; existing keys are never replaced.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { readSecret, getOrCreateSecret } = require('./aws');
const { SecretsManagerClient, CreateSecretCommand } = require('@aws-sdk/client-secrets-manager');

async function loadKeys() {
  const [priv, pub] = await Promise.all([readSecret('roadhub/jwt-private'), readSecret('roadhub/jwt-public')]);
  let privateKey;
  if (priv && pub) {
    privateKey = priv.PRIVATE_KEY;
  } else if (!priv && !pub) {
    const pair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
    const client = new SecretsManagerClient({});
    await client.send(new CreateSecretCommand({ Name: 'roadhub/jwt-private', SecretString: JSON.stringify({ PRIVATE_KEY: pair.privateKey }) }));
    await client.send(new CreateSecretCommand({ Name: 'roadhub/jwt-public', SecretString: JSON.stringify({ PUBLIC_KEY: pair.publicKey }) }));
    privateKey = pair.privateKey;
  } else {
    throw new Error('Only one of roadhub/jwt-private and roadhub/jwt-public exists. Run create-secrets.sh in the admin-service repo.');
  }
  const internal = await getOrCreateSecret('roadhub/internal', () => ({ INTERNAL_SIGNING_KEY: crypto.randomBytes(48).toString('hex') }));
  // Cloudflare's public test key (always passes); the tests also switch Turnstile off.
  await getOrCreateSecret('roadhub/turnstile', () => ({ TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA' }));
  return { privateKey, internalKey: internal.INTERNAL_SIGNING_KEY };
}

// A login token exactly like the one the Administration Service issues (RS256, 1 hour).
function userToken(keys, { id, name = 'Test User', tv = 0 }) {
  return jwt.sign({ typ: 'user', name, tv }, keys.privateKey, {
    algorithm: 'RS256', issuer: 'roadhub-admin', audience: 'roadhub-api', subject: id, expiresIn: 3600
  });
}

// A service-to-service token exactly like shared/internal-auth.js makes (HS256, 60 s).
function serviceToken(keys, { from, to, scope }) {
  return jwt.sign({ typ: 'service', scope: [].concat(scope) }, keys.internalKey, {
    algorithm: 'HS256', issuer: from, audience: to, expiresIn: 60, jwtid: crypto.randomUUID()
  });
}

module.exports = { loadKeys, userToken, serviceToken };
