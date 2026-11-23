// Test helper: starts THIS service as its own Node.js process (exactly like "npm start"),
// waits for GET /health, and stops it afterwards. Its log lines are kept for checks.
const { spawn } = require('child_process');
const path = require('path');
const { AWS_ENV } = require('./aws');

const ROOT = path.join(__dirname, '..', '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(url, child, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (child.exitCode !== null) throw new Error(`the service stopped while starting (exit code ${child.exitCode})`);
    try {
      if ((await fetch(url)).ok) return;
    } catch { /* not up yet */ }
    await sleep(100);
  }
  throw new Error(`${url} did not answer in time`);
}

async function startService({ port, env = {} }) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, ...AWS_ENV, PORT: String(port), NODE_ENV: 'test', ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const logs = [];
  const collect = (chunk) => chunk.toString().split('\n').filter(Boolean).forEach((l) => logs.push(l));
  child.stdout.on('data', collect);
  child.stderr.on('data', collect);
  const url = `http://127.0.0.1:${port}`;
  try {
    await waitFor(`${url}/health`, child);
  } catch (e) {
    child.kill('SIGKILL');
    throw new Error(`${e.message}\n${logs.slice(-20).join('\n')}`);
  }
  return {
    url,
    logs,
    async stop() {
      child.kill('SIGTERM');
      await sleep(200);
    }
  };
}

module.exports = { startService, sleep };
