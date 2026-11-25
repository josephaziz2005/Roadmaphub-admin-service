// Settings of the Administration Service. Table names can be changed with environment variables.
const awsRegion = process.env.AWS_REGION || 'us-east-1';
const awsAccountId = process.env.AWS_ACCOUNT_ID || '000000000000';
const opsTopicName = process.env.OPS_TOPIC_NAME || 'roadhub-ops-alerts';

module.exports = {
  tables: {
    users: process.env.USERS_TABLE || 'roadhub-users',
    merges: process.env.MERGES_TABLE || 'roadhub-merges',
    audit: process.env.AUDIT_TABLE || 'roadhub-audit'
  },
  sns: {
    opsTopicName,
    opsTopicArn: process.env.OPS_TOPIC_ARN || `arn:aws:sns:${awsRegion}:${awsAccountId}:${opsTopicName}`
  },
  cloudwatch: {
    logGroup: process.env.CLOUDWATCH_LOG_GROUP || '',
    logStream: process.env.CLOUDWATCH_LOG_STREAM || 'admin-service',
    enabled: process.env.CLOUDWATCH_LOGS !== 'off'
  },
  tokenLifetimeSeconds: 3600,          // logins last 1 hour
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 10,
  lockAfterFailures: 5,                // 5 wrong passwords in a row ...
  lockMinutes: 15,                     // ... lock the account for 15 minutes
  undoWindowDays: 7
};
