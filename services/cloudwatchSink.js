// Ships structured JSON log lines from shared/logger.js to AWS CloudWatch Logs (Floci or AWS).
// Keeps shared/ unchanged by registering through logger.addSink().
// Automatically creates the log group/stream if needed, batches writes, retries stale sequence
// tokens, redacts any accidental sensitive fields, and never throws into request handlers.
const {
  CloudWatchLogsClient,
  CreateLogGroupCommand,
  CreateLogStreamCommand,
  DescribeLogStreamsCommand,
  PutLogEventsCommand
} = require('@aws-sdk/client-cloudwatch-logs');
const config = require('../config');

const SENSITIVE_KEY = /password|secret|token|authorization|private|apikey|api_key/i;

function sanitizeValue(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitizeValue(item, depth + 1));
  if (typeof value === 'object') {
    const clean = {};
    for (const [k, v] of Object.entries(value)) {
      clean[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : sanitizeValue(v, depth + 1);
    }
    return clean;
  }
  return value;
}

function attachCloudWatchSink(logger, options = {}) {
  const logGroupName = options.logGroup !== undefined ? options.logGroup : config.cloudwatch.logGroup;
  const logStreamName = options.logStream || config.cloudwatch.logStream || 'admin-service';
  const enabled = options.enabled !== undefined ? options.enabled : config.cloudwatch.enabled;
  const flushIntervalMs = options.flushIntervalMs || 250;

  if (!enabled || !logGroupName) {
    return { flush: async () => {}, stop: async () => {} };
  }

  const client = options.client || new CloudWatchLogsClient({});
  const queue = [];
  let sequenceToken;
  let bootstrapped = false;
  let flushing = null;

  async function ensureStream() {
    if (bootstrapped) return;
    try {
      await client.send(new CreateLogGroupCommand({ logGroupName }));
    } catch (e) {
      if (e.name !== 'ResourceAlreadyExistsException') throw e;
    }
    try {
      await client.send(new CreateLogStreamCommand({ logGroupName, logStreamName }));
    } catch (e) {
      if (e.name !== 'ResourceAlreadyExistsException') throw e;
    }
    bootstrapped = true;
  }

  async function fetchSequenceToken() {
    const out = await client.send(new DescribeLogStreamsCommand({
      logGroupName,
      logStreamNamePrefix: logStreamName
    }));
    const match = (out.logStreams || []).find((s) => s.logStreamName === logStreamName);
    return match ? match.uploadSequenceToken : undefined;
  }

  async function sendBatch(events) {
    await ensureStream();
    try {
      const out = await client.send(new PutLogEventsCommand({
        logGroupName, logStreamName, logEvents: events, sequenceToken
      }));
      sequenceToken = out.nextSequenceToken;
    } catch (e) {
      if (e.name === 'InvalidSequenceTokenException' || e.name === 'DataAlreadyAcceptedException') {
        sequenceToken = e.expectedSequenceToken || await fetchSequenceToken();
        const out = await client.send(new PutLogEventsCommand({
          logGroupName, logStreamName, logEvents: events, sequenceToken
        }));
        sequenceToken = out.nextSequenceToken;
        return;
      }
      if (e.name === 'ResourceNotFoundException') {
        bootstrapped = false;
        sequenceToken = undefined;
      }
      throw e;
    }
  }

  async function flush() {
    if (flushing) return flushing;
    if (!queue.length) return;
    flushing = (async () => {
      while (queue.length) {
        const batch = queue.splice(0, 50).sort((a, b) => a.timestamp - b.timestamp);
        try {
          await sendBatch(batch);
        } catch {
          // Never crash or block the service if CloudWatch Logs is temporarily unreachable.
          break;
        }
      }
    })();
    try {
      await flushing;
    } finally {
      flushing = null;
    }
  }

  logger.addSink((_text, line) => {
    const safeLine = sanitizeValue(line);
    queue.push({ timestamp: Date.now(), message: JSON.stringify(safeLine) });
    if (queue.length >= 25) flush();
  });

  const timer = setInterval(() => { flush(); }, flushIntervalMs);
  timer.unref();

  return {
    flush,
    async stop() {
      clearInterval(timer);
      await Promise.race([flush(), new Promise((r) => setTimeout(r, 1500))]);
    }
  };
}

module.exports = { attachCloudWatchSink, sanitizeValue };
