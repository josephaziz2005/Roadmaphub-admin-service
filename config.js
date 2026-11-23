// Settings of the Administration Service. Table names can be changed with environment variables.
module.exports = {
  tables: {
    users: process.env.USERS_TABLE || 'roadhub-users',
    merges: process.env.MERGES_TABLE || 'roadhub-merges',
    audit: process.env.AUDIT_TABLE || 'roadhub-audit'
  },
  tokenLifetimeSeconds: 3600,          // logins last 1 hour
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 10,
  lockAfterFailures: 5,                // 5 wrong passwords in a row ...
  lockMinutes: 15,                     // ... lock the account for 15 minutes
  undoWindowDays: 7
};
