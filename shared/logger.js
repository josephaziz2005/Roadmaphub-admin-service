// One JSON line per log entry: { time, level, service, event, requestId, ... }.
// Never pass passwords, tokens, API keys, emails or request bodies to the logger.
// When CLOUDWATCH_LOG_GROUP is set, lines are also shipped to CloudWatch Logs (see cloudwatch.js).
let serviceName = process.env.SERVICE_NAME || 'roadhub';
const sinks = [];

function setServiceName(name) {
  serviceName = name;
}

function addSink(fn) {
  sinks.push(fn);
}

function write(level, event, data = {}) {
  const line = { time: new Date().toISOString(), level, service: serviceName, event, ...data };
  const text = JSON.stringify(line);
  if (level === 'ERROR') process.stderr.write(`${text}\n`);
  else process.stdout.write(`${text}\n`);
  for (const sink of sinks) {
    try { sink(text, line); } catch { /* logging must never break a request */ }
  }
}

module.exports = {
  setServiceName,
  addSink,
  info: (event, data) => write('INFO', event, data),
  warn: (event, data) => write('WARN', event, data),
  error: (event, data) => write('ERROR', event, data),
  // Security events (failed login, access denied, rate limited...) are tagged so
  // CloudWatch metric filters can count them.
  security: (event, data) => write('SECURITY', event, data)
};
