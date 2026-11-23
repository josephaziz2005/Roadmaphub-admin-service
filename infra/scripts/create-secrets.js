// Called by create-secrets.sh. Uses the AWS SDK so secret values never pass through the shell.
// Creates the secrets the Administration Service owns (other services only READ them):
//   roadhub/jwt-private  RS256 private key: ONLY this service may read it (it signs logins)
//   roadhub/jwt-public   RS256 public key: every service reads it to CHECK logins
//   roadhub/internal     key for service-to-service tokens (all three services)
//   roadhub/turnstile    Cloudflare Turnstile secret key (test key by default)
// roadhub/resend is created by the engagement-service repo (its owner uses it).
const path = require('path');
const crypto = require('crypto');
const ROOT = path.join(__dirname, '..', '..');
const {
  SecretsManagerClient, CreateSecretCommand, PutSecretValueCommand, DescribeSecretCommand
} = require(path.join(ROOT, 'node_modules', '@aws-sdk', 'client-secrets-manager'));

const client = new SecretsManagerClient({});
const say = (msg) => console.log(`  \x1b[32mOK\x1b[0m    ${msg}`);

async function exists(name) {
  try { await client.send(new DescribeSecretCommand({ SecretId: name })); return true; } catch { return false; }
}
async function save(name, value, { keepIfExists = false } = {}) {
  if (await exists(name)) {
    if (keepIfExists) return say(`${name} (kept)`);
    await client.send(new PutSecretValueCommand({ SecretId: name, SecretString: JSON.stringify(value) }));
    return say(`${name} updated`);
  }
  await client.send(new CreateSecretCommand({ Name: name, SecretString: JSON.stringify(value) }));
  return say(`${name} created`);
}

async function main() {
  // The signing key pair is made once and kept, so existing logins stay valid.
  // Set ROTATE_JWT=true to replace it (every user must log in again).
  const rotate = process.env.ROTATE_JWT === 'true';
  if (rotate || !(await exists('roadhub/jwt-private'))) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
    await save('roadhub/jwt-private', { PRIVATE_KEY: privateKey });
    await save('roadhub/jwt-public', { PUBLIC_KEY: publicKey });
  } else {
    say('roadhub/jwt-private (kept)');
    say('roadhub/jwt-public (kept)');
  }
  await save('roadhub/internal', { INTERNAL_SIGNING_KEY: crypto.randomBytes(48).toString('hex') }, { keepIfExists: !rotate });
  await save('roadhub/turnstile', {
    // Cloudflare's public test key: always passes. Use the real key from infra/.env for production.
    TURNSTILE_SECRET_KEY: process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA'
  });
}

main().catch((e) => { console.error(`  FAIL  secrets: ${e.name}: ${e.message}`); process.exit(1); });
