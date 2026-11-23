// Test helper: makes accounts through the real API, and administrators through the real script.
const { spawnSync } = require('child_process');
const path = require('path');
const { AWS_ENV } = require('./aws');
const { uniqueEmail } = require('./api');

const PASSWORD = 'Correct-horse-42';

async function newUser(call, name) {
  const email = uniqueEmail(name.toLowerCase());
  const r = await call('POST', '/api/auth/register', { body: { name, email, password: PASSWORD } });
  if (r.status !== 201) throw new Error(`register ${name}: ${r.status} ${JSON.stringify(r.data)}`);
  return { token: r.data.token, id: r.data.user.userId, email, name };
}

// Admins can only be created by the script (never through the public sign-up).
async function newAdmin(call) {
  const email = uniqueEmail('admin');
  const out = spawnSync(process.execPath, [path.join(__dirname, '..', '..', 'scripts', 'create-admin.js')], {
    env: { ...process.env, ...AWS_ENV, ADMIN_EMAIL: email, ADMIN_PASSWORD: PASSWORD, ADMIN_NAME: 'Test Admin' }, encoding: 'utf8'
  });
  if (out.status !== 0) throw new Error(`create-admin failed: ${out.stderr}`);
  const r = await call('POST', '/api/auth/login', { body: { email, password: PASSWORD } });
  return { token: r.data.token, id: r.data.user.userId, email, name: 'Test Admin' };
}

module.exports = { newUser, newAdmin, PASSWORD };
