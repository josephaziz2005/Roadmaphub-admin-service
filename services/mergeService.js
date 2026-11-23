// Duplicate merging across three services (a "saga": no single transaction can span three databases).
//   merge: record PREPARING -> roadmap.prepare -> engagement.prepare -> roadmap.complete
//          -> engagement.complete -> record COMMITTED (undo possible for 7 days)
//   if a step fails: compensate (engagement.abort, roadmap.undo/abort) -> record FAILED
// Every step is idempotent (Idempotency-Key = mergeId), so a retried call never applies twice.
const { randomUUID } = require('crypto');
const { http, events, logger } = require('../shared');
const repos = require('../repositories');
const services = require('../clients/services');
const config = require('../config');
const { titleSimilarity } = require('./similarity');

const { errors, AppError } = http;

function step(target, action, body, requestId) {
  const scope = target === 'roadmap' ? 'features:merge' : 'engagement:merge';
  const base = target === 'roadmap' ? '/internal/features/merges' : '/internal/engagement/merges';
  return services.callOk(target, { method: 'POST', path: `${base}/${action}`, body, scope, requestId, idempotencyKey: body.mergeId });
}

async function suggestions(featureId, requestId) {
  const source = await services.callOk('roadmap', { path: `/internal/features/${featureId}/resolve`, scope: 'features:read', requestId });
  const { items } = await services.callOk('roadmap', { path: '/internal/features/candidates', scope: 'features:read', requestId });
  return items
    .filter((c) => c.featureId !== source.canonicalId)
    .map((c) => ({ featureId: c.featureId, title: c.title, status: c.status, voteCount: c.voteCount || 0, score: titleSimilarity(source.title, c.title) }))
    .filter((c) => c.score >= 0.3)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
}

async function merge(admin, { sourceId, targetId }, ip, requestId) {
  if (sourceId === targetId) throw errors.badRequest('A request cannot be merged into itself.');
  const mergeId = randomUUID();
  const now = new Date().toISOString();
  await repos.merges.create({ mergeId, sourceId, targetId, state: 'PREPARING', actorId: admin.id, createdAt: now, updatedAt: now });
  const body = { mergeId, sourceId, targetId };
  const attempted = new Set(); // which steps that CHANGE data were started (they may have half-finished)
  try {
    attempted.add('roadmap.prepare');
    const prepared = await step('roadmap', 'prepare', body, requestId);
    const preview = await step('engagement', 'prepare', body, requestId); // read-only
    attempted.add('roadmap.complete');
    await step('roadmap', 'complete', body, requestId);
    attempted.add('engagement.complete');
    const counts = await step('engagement', 'complete', body, requestId);
    const record = await repos.merges.transition(mergeId, ['PREPARING'], 'COMMITTED', {
      committedAt: new Date().toISOString(),
      undoDeadline: new Date(Date.now() + config.undoWindowDays * 86400000).toISOString(),
      sourceTitle: prepared.source.title, targetTitle: prepared.target.title, sourceAuthorId: prepared.source.authorId,
      previousStatus: prepared.source.status, stats: { ...preview, ...counts }
    });
    await repos.audit.record({ action: 'merge.completed', actorId: admin.id, targetType: 'merge', targetId: mergeId, details: { sourceId, targetId, ...preview }, ip, requestId });
    await events.publish('admin', 'FeatureMerged', {
      mergeId, sourceId, targetId, sourceTitle: prepared.source.title, targetTitle: prepared.target.title,
      sourceAuthorId: prepared.source.authorId, actorId: admin.id
    }, { requestId });
    return record;
  } catch (err) {
    // Compensation: undo only the steps that were started, newest first, then record the failure.
    const repairs = [];
    if (attempted.has('engagement.complete')) {
      try { await step('engagement', 'abort', body, requestId); } catch { repairs.push('engagement'); }
    }
    if (attempted.has('roadmap.complete')) {
      try { await step('roadmap', 'undo', body, requestId); } catch {
        try { await step('roadmap', 'abort', body, requestId); } catch { repairs.push('roadmap'); } // complete never applied
      }
    } else if (attempted.has('roadmap.prepare')) {
      try { await step('roadmap', 'abort', body, requestId); } catch { repairs.push('roadmap'); }
    }
    await repos.merges.transition(mergeId, ['PREPARING'], repairs.length ? 'FAILED_NEEDS_REPAIR' : 'FAILED', {
      failedAt: new Date().toISOString(), failureCode: err.code || err.name, repairsPending: repairs
    });
    await repos.audit.record({ action: 'merge.failed', actorId: admin.id, targetType: 'merge', targetId: mergeId, details: { sourceId, targetId, code: err.code || err.name, repairs }, ip, requestId });
    logger.warn('MERGE_FAILED', { requestId, mergeId, code: err.code || err.name, repairs });
    if (err instanceof AppError) throw err;
    throw errors.unavailable('MERGE_FAILED', 'The merge could not be completed; nothing was changed.');
  }
}

async function undo(admin, mergeId, ip, requestId) {
  const record = await repos.merges.get(mergeId);
  if (!record) throw errors.notFound('MERGE_NOT_FOUND', 'This merge does not exist.');
  if (record.state === 'UNDONE') throw errors.conflict('ALREADY_UNDONE', 'This merge was already undone.');
  if (!['COMMITTED', 'UNDOING', 'UNDO_FAILED', 'FAILED_NEEDS_REPAIR'].includes(record.state)) {
    throw errors.conflict('NOT_UNDOABLE', `A merge in state ${record.state} cannot be undone.`);
  }
  if (record.state === 'COMMITTED' && new Date(record.undoDeadline) < new Date()) {
    throw errors.conflict('UNDO_EXPIRED', 'Merges can only be undone within 7 days.');
  }
  // Claim the undo so two admins cannot run it at the same time.
  const claimed = await repos.merges.transition(mergeId, [record.state], 'UNDOING', { undoStartedAt: new Date().toISOString() });
  if (!claimed) throw errors.conflict('MERGE_STATE_CHANGED', 'Someone else is changing this merge. Reload and try again.');
  const body = { mergeId, sourceId: record.sourceId, targetId: record.targetId };
  try {
    await step('engagement', 'undo', body, requestId);
    await step('roadmap', record.state === 'FAILED_NEEDS_REPAIR' ? 'abort' : 'undo', body, requestId);
  } catch (err) {
    await repos.merges.transition(mergeId, ['UNDOING'], 'UNDO_FAILED', { undoFailureCode: err.code || err.name });
    throw err instanceof AppError ? err : errors.unavailable('UNDO_FAILED', 'The undo could not finish. It is safe to try again.');
  }
  const done = await repos.merges.transition(mergeId, ['UNDOING'], 'UNDONE', { undoneAt: new Date().toISOString(), undoneBy: admin.id });
  await repos.audit.record({ action: 'merge.undone', actorId: admin.id, targetType: 'merge', targetId: mergeId, details: { sourceId: record.sourceId, targetId: record.targetId }, ip, requestId });
  await events.publish('admin', 'MergeUndone', { mergeId, sourceId: record.sourceId, targetId: record.targetId, actorId: admin.id }, { requestId });
  return done;
}

function publicMerge(m) {
  return {
    mergeId: m.mergeId, sourceId: m.sourceId, targetId: m.targetId, sourceTitle: m.sourceTitle, targetTitle: m.targetTitle,
    state: m.state, createdAt: m.createdAt, committedAt: m.committedAt, undoDeadline: m.undoDeadline, undoneAt: m.undoneAt,
    stats: m.stats, failureCode: m.failureCode,
    canUndo: (m.state === 'COMMITTED' && new Date(m.undoDeadline) > new Date()) || ['UNDO_FAILED', 'FAILED_NEEDS_REPAIR'].includes(m.state)
  };
}

module.exports = { suggestions, merge, undo, publicMerge };
