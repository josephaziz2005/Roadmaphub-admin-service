# Internal (service-to-service) API contract

Internal routes start with `/internal/`. The gateway **never** forwards `/internal/*` (it answers 404),
so only the services themselves can reach them, directly on their ports.
Each service finds the others through `ROADMAP_URL`, `ENGAGEMENT_URL` and `ADMIN_URL` (its own `.env`), so the three
repos can be deployed separately.

## Authentication of internal calls
Every internal request carries `X-Service-Token: <JWT>`:

| Claim | Value |
|---|---|
| `typ` | `service` (a user token has `typ: user`, so one can never be used as the other) |
| `iss` | calling service: `roadmap`, `engagement` or `admin` |
| `aud` | target service |
| `scope` | list of allowed actions, see the table below |
| `exp` | 60 seconds after issue |
| `jti` | random id (logged) |

Signed with HS256 using the internal key in Secrets Manager (`roadhub/internal`). User tokens are RS256 with
a different key, so they cannot pass this check. Each internal route checks `aud` and its required scope (403 otherwise).

| Caller → target | Scopes |
|---|---|
| engagement → roadmap | `features:read` |
| engagement → admin | `identity:read`, `identity:contacts` |
| roadmap → admin | `identity:read` |
| admin → roadmap | `features:read`, `features:merge` |
| admin → engagement | `engagement:merge` |

Every call also sends `X-Request-Id` (the id of the user request that caused it, for tracing in the logs).
Merge steps send `Idempotency-Key: <mergeId>`: repeating a step with the same key returns the same result and changes nothing twice.
Client rules (`shared/internal-client.js`, identical copy in each service repo): 3-second timeout; GET requests retried at most twice on network errors or 5xx; non-GET calls are retried only when they carry an `Idempotency-Key`. A target that still answers 5xx (or does not answer) is reported to the user as **503**; the target's own error text is never passed on. 4xx answers (404, 409 ...) are passed on with their code.

## roadmap-service (port 3001)
| Method and path | Scope | Purpose | Answers |
|---|---|---|---|
| GET `/internal/features/:id/resolve` | features:read | canonical id + status of a request (follows a merge link) | 200 `{featureId, canonicalId, exists, status, open, merged}`, 404 |
| POST `/internal/features/resolve-batch` `{ids}` (≤100) | features:read | summaries for "My votes" | 200 `{items:[{featureId, canonicalId, title, status, categoryName}]}` |
| GET `/internal/features/candidates?excludeId=` | features:read | open canonical requests for duplicate detection | 200 `{items:[{featureId, title, status}]}` |
| POST `/internal/features/merges/prepare` `{mergeId, sourceId, targetId}` | features:merge | validate both requests and lock the source | 200 `{source, target}`, 409 |
| POST `/internal/features/merges/complete` `{mergeId}` | features:merge | source → hidden, `mergedInto = target`, keep `previousStatus` | 200 |
| POST `/internal/features/merges/abort` `{mergeId}` | features:merge | release the lock after a failed merge | 200 |
| POST `/internal/features/merges/undo` `{mergeId}` | features:merge | restore the source and its previous status | 200, 409 |

## engagement-service (port 3002)
| Method and path | Scope | Purpose | Answers |
|---|---|---|---|
| POST `/internal/engagement/merges/prepare` `{mergeId, sourceId, targetId}` | engagement:merge | voter/comment numbers and overlap for the confirmation screen | 200 `{sourceVoters, targetVoters, sharedVoters, sourceComments}` |
| POST `/internal/engagement/merges/complete` `{mergeId, sourceId, targetId}` | engagement:merge | link source → target, recount the canonical request | 200 `{voteCount, commentCount}` |
| POST `/internal/engagement/merges/abort` `{mergeId}` | engagement:merge | remove the link if it was written | 200 |
| POST `/internal/engagement/merges/undo` `{mergeId}` | engagement:merge | remove the link, recount both requests | 200 |

## admin-service (port 3003)
| Method and path | Scope | Purpose | Answers |
|---|---|---|---|
| GET `/internal/identity/users/:id/status` | identity:read | is the account still active? role and token version | 200 `{userId, role, accountStatus, tokenVersion, suspendedUntil}`, 404 |
| POST `/internal/identity/users/contacts` `{userIds}` (≤50) | identity:contacts | names + emails for notification emails (skips banned) | 200 `{items:[{userId, name, email}]}` |
| POST `/internal/alerts/sns` | SNS message signature fields + topic check | receives `roadhub-ops-alerts` notifications | 200 |

## Who calls what, and why
| Workflow | Calls |
|---|---|
| Vote, comment, submit (any mutation) | service → admin `users/:id/status` (cached 10 s) so a suspended or banned user is stopped even with a valid JWT |
| Vote / comment on a request | engagement → roadmap `resolve` to find the canonical request and check it is open |
| My votes | engagement → roadmap `resolve-batch` |
| Duplicate suggestions | admin → roadmap `candidates` |
| Merge | admin → roadmap `prepare` → engagement `prepare` → roadmap `complete` → engagement `complete` (compensation with `abort` on failure) |
| Undo | admin → engagement `undo` → roadmap `undo` |
| Notification email | engagement worker → admin `contacts` |
