# RoadmapHub Public HTTP API Contract — Team Baseline v0.1

**Source of truth:** the routes/controllers of the three service repos (`roadhub-roadmap-service`, `roadhub-engagement-service`, `roadhub-admin-service`), split from the team baseline on 23 November 2026. The master copy of this file is in `roadhub-frontend/docs/`; each service repo keeps an identical copy in `docs/contracts/`. This document records the *current implementation*, not an assertion that Floci integration has passed. Changes to these paths, payloads or permissions require a reviewed PR touching this file (in every repo that holds a copy) and the associated tests.

## Common conventions

- Browser enters via `http://localhost:8080`. The gateway routes to three independent Express backends. `/api/health` reports gateway/replica health. Backend health routes use `/health` on ports 3001/3002/3003. Internal gateway is `127.0.0.1:8081`; never expose this to browsers or the Internet.
- Client sends `Authorization: Bearer <user JWT>` for authenticated endpoints. User tokens are RS256 (`user` role or `admin` role). Service-to-service calls require a distinct token: `X-Service-Token`. Normal browser clients **must not** call `/internal/*`.
- Requests with JSON bodies use `Content-Type: application/json`. Errors generally use `{ "error": { "code": "...", "message": "...", "details": ... } }`. A request correlation value is returned via `X-Request-Id` header. Do not assume `requestId` exists in JSON error bodies.
- Feature IDs, user IDs, comment IDs and merge IDs are UUIDs. Roles are lowercase `user` and `admin`. Public statuses: `under_review`, `planned`, `in_progress`, `shipped`. Merged is a hidden record state, not a fifth public status.
- List pagination uses opaque `cursor` and optional `limit`; do **not** use `page=` in the current API. Standard bad input 400, invalid login 401, insufficient privileges 403, missing records 404, conflict 409, throttling 429, unavailable dependency 503. Endpoint-specific behavior below takes precedence.
- Frontend must never directly access DynamoDB, Neon or another team's data tables. Cross-service operations use HTTP calls (see `docs/internal-api-contract.md`).

## Roadmap — S1 owned by Ziad, localhost:3001

| Method | Public path | Access | Request/parameters | Success |
|---|---|---|---|---|
| GET | `/api/categories` | Visitor | none | 200 `{categories:[{categoryId,name,...}]}` |
| GET | `/api/roadmap` | Visitor | optional `category`, `q`, `sort=votes\|newest`, `limit` (1–50) | 200 `{columns:{under_review,planned,in_progress,shipped}}`; each column contains `label`, `items`, `hasMore` |
| GET | `/api/features` | Visitor | **required** `status=under_review\|planned\|in_progress\|shipped`; optional `category`, `q`, `sort`, `cursor`, `limit` (1–50) | 200 `{items:[feature],nextCursor}` |
| GET | `/api/features/:id` | Visitor | UUID id | 200 `{feature}`; if merged, 307 with `Location` header and `{redirectTo,mergedFeature}` |
| GET | `/api/me/features` | Authenticated | optional `cursor`, `limit` | 200 `{items,nextCursor}` |
| POST | `/api/features` | `user` | JSON `{title,description,categoryId}`; `X-Turnstile-Token` where enabled | 201 `{feature}` |
| PATCH | `/api/features/:id` | `user`, owner | JSON partial `{title?,description?,categoryId?}`; only while Under Review | 200 `{feature}` |
| DELETE | `/api/features/:id` | `user`, owner | no JSON | 204 empty; not after votes/comments or while merged/locked |
| PATCH | `/api/features/:id/status` | `admin` | JSON `{status}` | 200 `{feature}`; 409 invalid transition |

Current validation: title 5–120 chars, description 10–2000 chars, categoryId 1–40 chars. Public category keys are seeded by `infra/scripts/create-tables.sh` in the roadmap repo. Status transitions in `services/statusRules.js` (roadmap repo): `under_review→planned`; `planned→under_review/in_progress`; `in_progress→planned/shipped`; `shipped` terminal. IDs use `featureId` in response payloads (not `id`).

## Engagement — S2 owned by Youssef, localhost:3002

| Method | Public path | Access | Request/parameters | Success |
|---|---|---|---|---|
| GET | `/api/features/:id/votes` | Visitor; user optionally authenticated | UUID id | 200 `{featureId,voteCount,commentCount,hasVoted}` |
| POST | `/api/features/:id/votes` | `user` | UUID id | 201 `{featureId,requestedId,voteCount,hasVoted:true}`; 409 duplicate |
| DELETE | `/api/features/:id/votes` | `user` | UUID id | **200** `{featureId,voteCount,hasVoted:false}` (current code, not 204) |
| GET | `/api/features/:id/comments` | Visitor | UUID id | 200 `{featureId,count,comments:[comment]}` |
| POST | `/api/features/:id/comments` | Authenticated | JSON `{body}`, 1–1000 chars; Turnstile token where enabled | 201 `{comment}` |
| PATCH | `/api/comments/:id` | Comment owner | JSON `{body}`, 1–1000 chars | 200 `{comment}` |
| DELETE | `/api/comments/:id` | Owner; currently also admin for moderation | UUID id | 204 empty |
| GET | `/api/me/votes` | Authenticated | none | 200 `{count,votes:[...]}` |
| GET | `/api/me/notifications` | Authenticated | none | 200 `{items:[...]}` |
| GET | `/api/engagement/dependencies` | Diagnostic | none | 200 when Roadmap/Admin internal APIs answer; otherwise 503 |

Current comment representation includes `commentId`, `featureId`, `userId`, `authorName`, `body`, `isTeamReply`, `edited`, `createdAt`, `updatedAt`, `fromMergedRequest`. The existing code permits authenticated admins to post team replies; confirm this with the team and update the role matrix and tests consistently before freeze if admin comments are out of scope.

## Administration — S3 owned by Joseph, localhost:3003

| Method | Public path | Access | Request/parameters | Success |
|---|---|---|---|---|
| POST | `/api/auth/register` | Visitor | JSON `{name,email,password}`, `X-Turnstile-Token` when enabled | 201 `{token,user}`; role cannot be supplied |
| POST | `/api/auth/login` | Visitor | JSON `{email,password}` | 200 `{token,user}` |
| GET | `/api/auth/me` | Authenticated | none | 200 `{user}` |
| POST | `/api/auth/logout` | Authenticated | none | 204 empty; token version invalidated |
| GET | `/api/admin/features/:id/duplicate-suggestions` | `admin` | UUID id | 200 `{suggestions:[{featureId,title,status,voteCount,score}]}` |
| POST | `/api/admin/features/:id/merge` | `admin` | JSON `{targetId}`; source feature is URL `:id` | **201** `{merge}` |
| GET | `/api/admin/merges` | `admin` | optional `cursor` | 200 `{items,nextCursor}` |
| POST | `/api/admin/merges/:mergeId/undo` | `admin` | UUID mergeId | 200 `{merge}`; 409 if ineligible |
| GET | `/api/admin/users` | `admin` | optional `status=active\|suspended\|banned`, `q` | 200 `{users:[...]}` |
| PATCH | `/api/admin/users/:id/status` | `admin` | JSON `{action:suspend\|ban\|restore,days?,reason?}` | 200 `{user}` |
| GET | `/api/admin/audit` | `admin` | query parameters per controller | 200 audit records |
| GET | `/api/admin/security-events` | `admin` | query parameters per controller | 200 security events |

The registration name is 2–60 chars; passwords follow `services/passwordPolicy.js` (admin repo). Admin registration is **not** available publicly: an initial administrator is created with `infra/scripts/create-admin.sh` in the admin repo. A successful merge must preserve the 7-day undo workflow and canonical feature redirection.

## Error and authorization examples

- `POST /api/features` without JWT → 401; with admin JWT → 403.
- User B attempts to edit user A's feature → 403 (`NOT_OWNER`).
- A second vote on the same effective canonical request → 409 (`ALREADY_VOTED`).
- Invalid status transition → 409 (`INVALID_TRANSITION`).
- `/internal/...` through the public gateway → 404. An internal service route called without `X-Service-Token` → 401.

## Important unverified / pending items

- This is the **current checkpoint code**, not yet verified on the team's Floci version; rerun integration tests before marking passed.
- Browser frontend is missing; service URLs, payloads, auth headers and error handling above are the starting frontend specification.
- Notification worker, complete AWS provisioning, public deployment and Postgres repositories remain unfinished.
- Decide/comment-role discrepancy (admins currently allowed to comment), and test the final policy.
- Review concurrency safety, idempotency and recovery for multi-service merges rather than treating passing unit tests as a production guarantee.
