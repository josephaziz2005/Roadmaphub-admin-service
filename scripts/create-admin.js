// Creates the first administrator (public sign-up can only make "user" accounts).
// Reads ADMIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD from the environment (infra/.env via create-admin.sh).
// If the account exists, it is promoted to admin and its old sessions are ended.
require('dotenv').config({ quiet: true });
const bcrypt = require('bcryptjs');
const repos = require('../repositories');
const config = require('../config');
const { checkPassword } = require('../services/passwordPolicy');

async function main() {
  const name = (process.env.ADMIN_NAME || 'Product Team Admin').trim();
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!email) throw new Error('ADMIN_EMAIL is empty (set it in infra/.env)');
  const existing = await repos.users.findByEmail(email);
  if (existing) {
    await repos.users.setRole(existing.userId, 'admin');
    console.log(`  OK    ${email} is now an admin (old sessions ended)`);
    return;
  }
  const problem = checkPassword(password, email);
  if (problem) throw new Error(`ADMIN_PASSWORD: ${problem}`);
  const user = await repos.users.createUser({ name, email, passwordHash: await bcrypt.hash(password, config.bcryptRounds), role: 'admin' });
  await repos.audit.record({ action: 'user.admin_created', actorId: 'script', targetType: 'user', targetId: user.userId });
  console.log(`  OK    admin ${email} created`);
}

main().catch((e) => { console.error(`  FAIL  create-admin: ${e.message}`); process.exit(1); });
