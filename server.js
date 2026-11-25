// Starts the Administration and Triage Service (S3) on its own port (independent process).
require('dotenv').config({ quiet: true });
process.env.SERVICE_NAME = process.env.SERVICE_NAME || 'admin';
const { logger } = require('./shared');
const { attachCloudWatchSink } = require('./services/cloudwatchSink');
const app = require('./app');

logger.setServiceName(process.env.SERVICE_NAME);
const cwSink = attachCloudWatchSink(logger);
const port = Number(process.env.PORT) || 3003;
const server = app.listen(port, () => logger.info('SERVICE_STARTED', { port, pid: process.pid }));

// Stop cleanly (flush pending CloudWatch Logs, then let the gateway mark this replica down).
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    cwSink.stop().finally(() => server.close(() => process.exit(0)));
  });
}
