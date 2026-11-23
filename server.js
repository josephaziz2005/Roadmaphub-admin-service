// Starts the Administration and Triage Service (S3) on its own port (independent process).
require('dotenv').config({ quiet: true });
process.env.SERVICE_NAME = process.env.SERVICE_NAME || 'admin';
const { logger } = require('./shared');
const app = require('./app');

logger.setServiceName(process.env.SERVICE_NAME);
const port = Number(process.env.PORT) || 3003;
const server = app.listen(port, () => logger.info('SERVICE_STARTED', { port, pid: process.pid }));

// Stop cleanly (the gateway's health check then marks this replica down).
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
