// The Administration Service's client for the other services (real HTTP calls with service tokens).
const { internalClient } = require('../shared');

module.exports = internalClient.createInternalClient('admin');
