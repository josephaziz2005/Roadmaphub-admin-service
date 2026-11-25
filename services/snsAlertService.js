// Handles AWS SNS HTTP notifications for operational alerts (topic: roadhub-ops-alerts).
// Validates the SNS envelope, signature metadata fields, SigningCertURL host, and TopicArn
// before confirming subscriptions or recording OPS_ALERT items in roadhub-audit.
const { SNSClient, ConfirmSubscriptionCommand } = require('@aws-sdk/client-sns');
const { http, logger } = require('../shared');
const repos = require('../repositories');
const config = require('../config');

const { errors } = http;
const sns = new SNSClient({});

const ALLOWED_TYPES = new Set(['SubscriptionConfirmation', 'Notification', 'UnsubscribeConfirmation']);
const ALLOWED_SIG_VERSIONS = new Set(['1', '2']);
const AWS_SNS_CERT_HOST = /^sns\.[a-z0-9-]+\.amazonaws\.com$/i;
const LOCAL_CERT_HOSTS = new Set(['localhost', '127.0.0.1', 'floci', 'host.docker.internal']);
const SENSITIVE_KEY = /password|secret|token|authorization|apikey|api_key|private/i;

function parseBody(raw) {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch { /* handled below */ }
  }
  throw errors.badRequest('SNS payload must be a valid JSON object.');
}

function isAllowedCertUrl(certUrl) {
  if (typeof certUrl !== 'string' || !certUrl) return false;
  let parsed;
  try { parsed = new URL(certUrl); } catch { return false; }
  if (parsed.protocol === 'https:' && AWS_SNS_CERT_HOST.test(parsed.hostname) && parsed.pathname.endsWith('.pem')) {
    return true;
  }
  // Local Floci emulator certificates (when AWS_ENDPOINT_URL points to Floci)
  if (process.env.AWS_ENDPOINT_URL && (parsed.protocol === 'http:' || parsed.protocol === 'https:') && LOCAL_CERT_HOSTS.has(parsed.hostname)) {
    return true;
  }
  return false;
}

function validateEnvelope(payload, { ip, requestId }) {
  const { Type, MessageId, TopicArn, SignatureVersion, Signature } = payload;
  const certUrl = payload.SigningCertURL || payload.SigningCertUrl;

  if (typeof Type !== 'string' || !ALLOWED_TYPES.has(Type)) {
    throw errors.badRequest('SNS Type must be SubscriptionConfirmation, Notification, or UnsubscribeConfirmation.', { field: 'Type' });
  }
  if (typeof MessageId !== 'string' || !MessageId.trim() || MessageId.length > 128) {
    throw errors.badRequest('SNS MessageId is required.', { field: 'MessageId' });
  }
  if (typeof TopicArn !== 'string' || !TopicArn.trim()) {
    throw errors.badRequest('SNS TopicArn is required.', { field: 'TopicArn' });
  }
  if (TopicArn !== config.sns.opsTopicArn) {
    logger.security('SNS_TOPIC_MISMATCH', { requestId, ip, gotTopicArn: TopicArn });
    throw errors.forbidden('SNS_TOPIC_MISMATCH', 'SNS notifications from this topic are not accepted.');
  }

  // Signature metadata validation (required unless local Floci omits signature fields on localhost).
  const hasAnySigField = Boolean(SignatureVersion || Signature || certUrl);
  const localEmulator = Boolean(process.env.AWS_ENDPOINT_URL);
  if (hasAnySigField || !localEmulator) {
    if (!ALLOWED_SIG_VERSIONS.has(String(SignatureVersion || ''))) {
      logger.security('SNS_SIGNATURE_INVALID', { requestId, ip, reason: 'SignatureVersion' });
      throw errors.forbidden('SNS_SIGNATURE_INVALID', 'SNS SignatureVersion must be 1 or 2.');
    }
    if (typeof Signature !== 'string' || Signature.trim().length < 16) {
      logger.security('SNS_SIGNATURE_INVALID', { requestId, ip, reason: 'Signature' });
      throw errors.forbidden('SNS_SIGNATURE_INVALID', 'SNS Signature field is missing or invalid.');
    }
    if (!isAllowedCertUrl(certUrl)) {
      logger.security('SNS_CERT_URL_REJECTED', { requestId, ip });
      throw errors.forbidden('SNS_CERT_URL_INVALID', 'SNS SigningCertURL is not from a trusted SNS host.');
    }
  }
}

function cleanText(value, max = 500) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > max ? `${trimmed.slice(0, max)}...` : trimmed;
}

// Safely extract non-secret fields from either a CloudWatch Alarm JSON or plain alert text.
function summarizeMessage(message) {
  if (typeof message !== 'string') return { summary: '' };
  const trimmed = message.trim();
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const out = {};
      if (parsed.AlarmName) out.alarmName = cleanText(String(parsed.AlarmName), 120);
      if (parsed.NewStateValue) out.newState = cleanText(String(parsed.NewStateValue), 40);
      if (parsed.NewStateReason) out.reason = cleanText(String(parsed.NewStateReason), 400);
      if (parsed.source) out.source = cleanText(String(parsed.source), 80);
      if (parsed.eventType) out.eventType = cleanText(String(parsed.eventType), 80);
      if (parsed.reason && !out.reason) out.reason = cleanText(String(parsed.reason), 400);
      if (parsed.message) out.summary = cleanText(String(parsed.message), 500);
      if (Object.keys(out).length) return out;
      // Fallback: copy up to 6 safe primitive fields, skipping anything sensitive
      for (const [k, v] of Object.entries(parsed)) {
        if (SENSITIVE_KEY.test(k)) continue;
        if (['string', 'number', 'boolean'].includes(typeof v)) {
          out[k] = typeof v === 'string' ? cleanText(v, 200) : v;
        }
        if (Object.keys(out).length >= 6) break;
      }
      if (Object.keys(out).length) return out;
    }
  } catch { /* plain text message */ }
  return { summary: cleanText(trimmed, 500) };
}

async function handleMessage(rawBody, { ip, requestId, snsClient = sns } = {}) {
  const payload = parseBody(rawBody);
  validateEnvelope(payload, { ip, requestId });

  if (payload.Type === 'SubscriptionConfirmation') {
    if (typeof payload.Token !== 'string' || !payload.Token.trim()) {
      throw errors.badRequest('SNS Token is required for SubscriptionConfirmation.', { field: 'Token' });
    }
    await snsClient.send(new ConfirmSubscriptionCommand({
      TopicArn: payload.TopicArn,
      Token: payload.Token
    }));
    await repos.audit.record({
      type: 'OPS_ALERT',
      action: 'sns.subscription_confirmed',
      actorId: 'sns',
      targetType: 'sns',
      targetId: payload.TopicArn,
      details: { messageId: payload.MessageId },
      ip,
      requestId
    });
    logger.info('SNS_SUBSCRIPTION_CONFIRMED', { requestId, topicArn: payload.TopicArn, messageId: payload.MessageId });
    return { ok: true, status: 'confirmed', topicArn: payload.TopicArn };
  }

  if (payload.Type === 'Notification') {
    if (typeof payload.Message !== 'string' || !payload.Message.trim()) {
      throw errors.badRequest('SNS Message is required for Notification.', { field: 'Message' });
    }
    const subject = cleanText(payload.Subject, 160) || 'Operations Alert';
    const summary = summarizeMessage(payload.Message);
    await repos.audit.record({
      type: 'OPS_ALERT',
      action: 'sns.ops_alert',
      actorId: 'sns',
      targetType: 'sns',
      targetId: payload.TopicArn,
      details: {
        messageId: payload.MessageId,
        subject,
        timestamp: cleanText(payload.Timestamp, 64),
        ...summary
      },
      ip,
      requestId
    });
    logger.warn('OPS_ALERT_RECEIVED', { requestId, messageId: payload.MessageId, subject });
    return { ok: true, status: 'received', messageId: payload.MessageId };
  }

  // UnsubscribeConfirmation
  await repos.audit.record({
    type: 'OPS_ALERT',
    action: 'sns.unsubscribed',
    actorId: 'sns',
    targetType: 'sns',
    targetId: payload.TopicArn,
    details: { messageId: payload.MessageId },
    ip,
    requestId
  });
  logger.warn('SNS_UNSUBSCRIBED', { requestId, topicArn: payload.TopicArn, messageId: payload.MessageId });
  return { ok: true, status: 'acknowledged', topicArn: payload.TopicArn };
}

module.exports = { handleMessage, isAllowedCertUrl, summarizeMessage };
