// Test helper: a FAKE neighbour service. It answers the internal routes that this service calls,
// checks the service token like the real service would (key, audience), and records every call,
// so a test can check WHAT this service asked, with WHICH scope and request id.
//   const roadmap = await startFake('roadmap', keys.internalKey, [
//     { method: 'GET', path: /^\/internal\/features\/([^/]+)\/resolve$/, reply: ({ params }) => ({ status: 200, body: {...} }) }
//   ]);
const http = require('http');
const jwt = require('jsonwebtoken');

let sequence = 0; // one counter for every fake in this test process: shows the real order of calls

function startFake(name, internalKey, routes) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', async () => {
      const send = (status, data) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(data === undefined ? '' : JSON.stringify(data));
      };
      const path = req.url.split('?')[0];
      let token = null;
      try {
        token = jwt.verify(req.headers['x-service-token'] || '', internalKey, { algorithms: ['HS256'], audience: name });
      } catch { /* token missing or invalid */ }
      const call = {
        seq: (sequence += 1), method: req.method, path, url: req.url, body: raw ? JSON.parse(raw) : undefined, token,
        requestId: req.headers['x-request-id'], idempotencyKey: req.headers['idempotency-key']
      };
      calls.push(call);
      if (!token) return send(401, { error: { code: 'UNAUTHENTICATED', message: 'Service token is not valid.' } });
      const route = routes.find((r) => r.method === req.method && r.path.test(path));
      if (!route) return send(404, { error: { code: 'NOT_FOUND', message: `fake ${name}: no route ${req.method} ${path}` } });
      try {
        const out = await route.reply({ ...call, params: path.match(route.path).slice(1) });
        send(out.status || 200, out.body);
      } catch (e) {
        send(500, { error: { code: 'FAKE_ERROR', message: e.message } });
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${server.address().port}`,
      calls,
      callsTo: (pattern) => calls.filter((c) => pattern.test(c.path)),
      clear: () => { calls.length = 0; },
      stop: () => new Promise((done) => { server.closeAllConnections(); server.close(() => done()); })
    }));
  });
}

module.exports = { startFake };
