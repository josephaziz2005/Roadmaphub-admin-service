// Publishes business events to the EventBridge bus "roadhub-events".
// Rules on the bus send them to SQS queues (e-mails, vote counts) and to CloudWatch Logs.
// Publishing never breaks the user's request: a failure is logged (see docs/limitations.md
// for the outbox improvement that would make delivery guaranteed).
const { EventBridgeClient, PutEventsCommand } = require('@aws-sdk/client-eventbridge');
const { randomUUID } = require('crypto');
const logger = require('./logger');

const client = new EventBridgeClient({});
const BUS = process.env.EVENT_BUS_NAME || 'roadhub-events';

async function publish(source, detailType, detail, { requestId } = {}) {
  if (process.env.EVENTS === 'off') return false;
  const eventId = randomUUID();
  try {
    const out = await client.send(new PutEventsCommand({
      Entries: [{
        EventBusName: BUS,
        Source: `roadhub.${source}`,
        DetailType: detailType,
        Detail: JSON.stringify({ eventId, occurredAt: new Date().toISOString(), requestId, ...detail })
      }]
    }));
    if (out.FailedEntryCount) throw new Error(out.Entries[0].ErrorMessage || 'entry failed');
    logger.info('EVENT_PUBLISHED', { requestId, eventType: detailType, eventId });
    return true;
  } catch (e) {
    logger.error('EVENT_PUBLISH_FAILED', { requestId, eventType: detailType, eventId, reason: e.name });
    return false;
  }
}

module.exports = { publish, BUS };
