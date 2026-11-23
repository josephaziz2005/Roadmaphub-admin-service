// Signs user logins with RS256. The PRIVATE key is in Secrets Manager (roadhub/jwt-private) and only
// this service's IAM role may read it. The other services hold only the public key, so they can
// CHECK a login but never CREATE one.
const jwt = require('jsonwebtoken');
const { secrets, userAuth } = require('../shared');
const config = require('../config');

async function signUserToken(user) {
  const { PRIVATE_KEY } = await secrets.getSecret('roadhub/jwt-private');
  return jwt.sign(
    { typ: 'user', role: user.role, tv: user.tokenVersion || 0, name: user.name },
    PRIVATE_KEY,
    { algorithm: 'RS256', subject: user.userId, issuer: userAuth.ISSUER, audience: userAuth.AUDIENCE, expiresIn: config.tokenLifetimeSeconds }
  );
}

module.exports = { signUserToken };
