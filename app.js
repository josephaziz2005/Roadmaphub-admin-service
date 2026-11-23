// Administration and Triage Service (S3): its own Express app (independent from the other two services).
// server.js starts it. Order of middleware = order every request passes through.
const express = require('express');
const cors = require('cors');
const { http } = require('./shared');
const publicRoutes = require('./routes/public');
const internalRoutes = require('./routes/internal');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback'); // the gateway on this PC forwards the real client address

app.use(http.requestId);        // X-Request-Id for tracing across services
app.use(http.requestLogger);    // one JSON log line per request
app.use(http.securityHeaders);  // nosniff, DENY frames, CSP for JSON answers

// Health check used by the gateway (load balancer) every few seconds
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'admin', pid: process.pid, port: Number(process.env.PORT) });
});

// Internal routes: called by the other services only (service token required, no CORS)
app.use('/internal', express.json({ limit: '32kb' }), internalRoutes);

// Public API: browser calls through the gateway
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:4566,http://localhost:8080')
  .split(',').map((o) => o.trim()).filter(Boolean);
app.use('/api', cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Turnstile-Token', 'X-Request-Id'],
  exposedHeaders: ['X-Request-Id', 'X-Served-By']
}));
app.use('/api', http.requireJson, express.json({ limit: '10kb' }), publicRoutes);

app.use(http.notFound);
app.use(http.errorHandler);

module.exports = app;
