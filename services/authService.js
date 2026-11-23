// Registration, login and logout (business rules only; no HTTP here).
const bcrypt = require('bcryptjs');
const { http, logger, userAuth } = require('../shared');
const repos = require('../repositories');
const config = require('../config');
const { checkPassword } = require('./passwordPolicy');
const { signUserToken } = require('./tokenService');

const { errors, AppError } = http;
// Compared against when the e-mail is unknown, so a wrong e-mail takes as long as a wrong password
// (an attacker cannot tell which e-mails have accounts).
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing-1', 10);

function profile(user) {
  return {
    userId: user.userId, name: user.name, email: user.email, role: user.role,
    accountStatus: userAuth.effectiveStatus(user), suspendedUntil: user.suspendedUntil, createdAt: user.createdAt
  };
}

async function register({ name, email, password, ip, requestId }) {
  const problem = checkPassword(password, email);
  if (problem) throw errors.badRequest(problem, { field: 'password' });
  const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
  const user = await repos.users.createUser({ name, email, passwordHash, role: 'user' }); // public sign-up is ALWAYS "user"
  if (!user) throw errors.conflict('EMAIL_TAKEN', 'An account with this e-mail already exists.');
  await repos.audit.record({ action: 'user.registered', actorId: user.userId, targetType: 'user', targetId: user.userId, ip, requestId });
  return { token: await signUserToken(user), user: profile(user) };
}

async function failedLogin(user, ip, requestId) {
  logger.security('LOGIN_FAILED', { requestId, ip, userId: user ? user.userId : undefined });
  await repos.audit.record({ type: 'SECURITY', action: 'LOGIN_FAILED', actorId: user ? user.userId : undefined, ip, requestId });
  if (user) {
    const count = await repos.users.recordFailedLogin(user.userId);
    if (count >= config.lockAfterFailures) {
      const until = new Date(Date.now() + config.lockMinutes * 60000).toISOString();
      await repos.users.lockAccount(user.userId, until);
      logger.security('ACCOUNT_LOCKED', { requestId, ip, userId: user.userId });
      await repos.audit.record({ type: 'SECURITY', action: 'ACCOUNT_LOCKED', actorId: user.userId, targetType: 'user', targetId: user.userId, ip, requestId });
    }
  }
  // Same answer for "no such e-mail" and "wrong password".
  return errors.unauthenticated('E-mail or password is incorrect.');
}

async function login({ email, password, ip, requestId }) {
  const user = await repos.users.findByEmail(email);
  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH);
    throw await failedLogin(null, ip, requestId);
  }
  if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
    logger.security('LOGIN_WHILE_LOCKED', { requestId, ip, userId: user.userId });
    throw new AppError(423, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try again in 15 minutes.');
  }
  if (!(await bcrypt.compare(password, user.passwordHash))) throw await failedLogin(user, ip, requestId);
  if (userAuth.effectiveStatus(user) === 'banned') throw errors.forbidden('ACCOUNT_BANNED', 'This account is banned.');
  await repos.users.recordSuccessfulLogin(user.userId);
  return { token: await signUserToken(user), user: profile(user) };
}

// Ends EVERY session of this user (token version + 1), so a stolen token stops working too.
async function logout(userId, ip, requestId) {
  await repos.users.bumpTokenVersion(userId);
  await repos.audit.record({ action: 'user.logged_out', actorId: userId, targetType: 'user', targetId: userId, ip, requestId });
}

async function me(userId) {
  const user = await repos.users.findById(userId);
  if (!user) throw errors.notFound('USER_NOT_FOUND', 'Account not found.');
  return profile(user);
}

module.exports = { register, login, logout, me, profile };
