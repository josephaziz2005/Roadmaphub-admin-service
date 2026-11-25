# roadhub-admin-service: Administration and Triage Service (S3)

RoadmapHub · Team 22 (Lab Group A-3) · Cloud Computing and Cloud Security (26CSCN29H)
**Owner:** Joseph Maged Aziz (240028)

Owns the accounts: sign-up, login (RS256 tokens), logout, lockout after 5 wrong passwords, and the account state
the other services check. Admins find duplicate requests, merge them (a saga across all three services, with
undo within 7 days), suspend, ban or restore users, and read the audit log and security events.

RoadmapHub is four repositories: `roadhub-roadmap-service`, `roadhub-engagement-service`, **admin (this one)**,
and `roadhub-frontend` (website, gateway, whole-system tests, team docs).

## API
Public (browsers reach it through the gateway on :8080). Full details: `docs/contracts/public-api-contract.md`.

| Method | Path | Who |
|---|---|---|
| POST | `/api/auth/register`, `/api/auth/login` | visitor |
| GET | `/api/auth/me` | logged in |
| POST | `/api/auth/logout` (ends every session) | logged in |
| GET | `/api/admin/features/:id/duplicate-suggestions` | admin |
| POST | `/api/admin/features/:id/merge` `{targetId}` | admin |
| GET | `/api/admin/merges`; POST `/api/admin/merges/:mergeId/undo` | admin |
| GET | `/api/admin/users`; PATCH `/api/admin/users/:id/status` `{action: suspend/ban/restore}` | admin |
| GET | `/api/admin/audit`, `/api/admin/security-events` | admin |

Internal (other services only, `X-Service-Token`). Details: `docs/contracts/internal-api-contract.md`.

| Path | Scope | Caller |
|---|---|---|
| GET `/internal/identity/users/:id/status` | `identity:read` | roadmap, engagement |
| POST `/internal/identity/users/contacts` | `identity:contacts` | engagement (notification worker) |
| POST `/internal/alerts/sns` | SNS envelope + TopicArn + SigningCertURL check | AWS SNS (`roadhub-ops-alerts`) |

This service calls: roadmap `resolve` / `candidates` (`features:read`) and `merges/*` (`features:merge`), and
engagement `merges/*` (`engagement:merge`), always with `Idempotency-Key = mergeId`.

## Data and AWS
- **DynamoDB** (only this service uses these 3 tables): `roadhub-users` (with e-mail lock items: one account per e-mail),
  `roadhub-merges` (saga state), `roadhub-audit` (actions, security events, and SNS `OPS_ALERT` entries).
- **Secrets Manager**: creates and owns `roadhub/jwt-private` (only this service reads it), `roadhub/jwt-public`,
  `roadhub/internal` and `roadhub/turnstile`. **Run its secrets script first on a new Floci**: the other services need them.
- **SNS**: `infra/scripts/create-sns.sh` creates `roadhub-ops-alerts` and subscribes `POST /internal/alerts/sns`.
- **CloudWatch Logs & Alarm**: `services/cloudwatchSink.js` ships redacted JSON logs to `/roadhub/admin`; `infra/scripts/create-monitoring.sh` sets 14-day retention, `LOGIN_FAILED` and `ACCESS_DENIED` metric filters, and `roadhub-admin-brute-force-alarm` → `roadhub-ops-alerts`.
- **EventBridge**: `infra/scripts/create-eventbridge.sh` creates bus `roadhub-events` and `roadhub-admin-events-rule` for `FeatureMerged`, `MergeUndone`, `UserSuspended`, `UserBanned`, and `UserRestored`.
- **IAM (least privilege)**: `infra/scripts/create-iam.sh` creates `roadhub-admin-role` + `roadhub-admin-least-privilege` with zero wildcards (`Resource: "*"`), scoped exclusively to this service's own tables, secrets, bus, topic, and log group.

## Run it (Windows: Git Bash)
Needs Node.js 20+, Docker Desktop and the AWS CLI.
```bash
npm install
docker compose -f infra/floci/docker-compose.yml up -d   # Floci (same file in every repo: one Floci per PC)
cp infra/.env.example infra/.env                         # first admin's e-mail and a strong password (never commit it)
npm run setup:all                                        # secrets, 3 tables, SNS, CloudWatch/alarm, EventBridge, IAM
bash infra/scripts/create-admin.sh                       # first administrator
npm run check:aws                                        # verify all 6 AWS services on Floci (18/18 checks)
cp .env.example .env                                     # ports and the other services' URLs (no secrets)
npm start                                                # http://localhost:3003/health
```
Merging needs the roadmap and engagement services running. For the whole system, use `roadhub-frontend`.

## Tests
```bash
npm test
```
Starts this service as its own process with its real tables, plus a **fake roadmap service** and a **fake
engagement service**, so it needs only Floci and the setup scripts.
- `tests/auth.test.js`: sign-up (role cannot be chosen, weak password, duplicate e-mail, 3 sign-ups at once),
  login (same message for unknown e-mail and wrong password, lockout → 423), forged tokens, logout, internal endpoints and scopes.
- `tests/admin.test.js`: admin-only access, suspend/restore/ban (old tokens stop, banned login refused, audit),
  duplicate suggestions, the merge saga (step order, one request id, Idempotency-Key, scopes), compensation when
  engagement fails half-way (FAILED, 503, no leaked error text), a 409 from roadmap, undo and second undo, security events.
- `tests/sns.test.js`: SNS webhook validation (`400`), TopicArn/SigningCertURL/signature checks (`403`), sensitive-key redaction, admin-only `OPS_ALERT` visibility, and live Floci SNS publish → HTTP delivery.
- `tests/cloudwatch.test.js`: recursive secret redaction, live `LOGIN_FAILED` and `ACCESS_DENIED` delivery to Floci CloudWatch Logs `/roadhub/admin` with zero leaked secrets, and metric filter checks.
- `tests/eventbridge.test.js`: `roadhub-events` bus/rule verification and live EventBridge pattern matching + delivery for moderation events.
- `tests/iam.test.js`: `roadhub-admin-role` trust policy and zero-wildcard least-privilege boundary assertions.

## Folders
`routes/` → `controllers/` → `services/` (business rules: auth, tokens, merge saga, moderation) → `repositories/`
(DynamoDB). `scripts/create-admin.js` makes the first admin, `shared/` is the common kit (identical in the three
service repos, see `shared/README.md`), `infra/` holds the Floci scripts, `tests/` the tests.
