// Login checks for the Administration Service. It owns the accounts, so it reads the
// account state straight from its own table (the other services ask this service over HTTP).
const { userAuth } = require('../shared');
const repos = require('../repositories');

module.exports = userAuth.createUserAuth({
  cacheMs: 0, // always fresh here
  getStatus: async (userId) => {
    const user = await repos.users.findById(userId);
    return user && { role: user.role, accountStatus: user.accountStatus, tokenVersion: user.tokenVersion || 0, suspendedUntil: user.suspendedUntil };
  }
});
