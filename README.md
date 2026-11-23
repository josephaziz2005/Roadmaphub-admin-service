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

This service calls: roadmap `resolve` / `candidates` (`features:read`) and `merges/*` (`features:merge`), and
engagement `merges/*` (`engagement:merge`), always with `Idempotency-Key = mergeId`.

## Data and AWS
- DynamoDB tables (only this service uses them): `roadhub-users` (with e-mail lock items: one account per e-mail),
  `roadhub-merges` (saga state), `roadhub-audit`.
- Secrets Manager: creates and owns `roadhub/jwt-private` (only this service reads it), `roadhub/jwt-public`,
  `roadhub/internal` and `roadhub/turnstile`. **Run its secrets script first on a new Floci**: the other services need them.
- SNS subscription, CloudWatch metric filter and alarm: planned (Phase 11), see `docs/service-boundaries.md` in roadhub-frontend.

## Run it (Windows: Git Bash)
Needs Node.js 20+, Docker Desktop and the AWS CLI.
```bash
npm install
docker compose -f infra/floci/docker-compose.yml up -d   # Floci (same file in every repo: one Floci per PC)
bash infra/scripts/create-tables.sh                      # this service's 3 tables
cp infra/.env.example infra/.env                         # first admin's e-mail and a strong password (never commit it)
bash infra/scripts/create-secrets.sh                     # login keys, internal key, Turnstile
bash infra/scripts/create-admin.sh                       # first administrator
cp .env.example .env                                     # ports and the other services' URLs (no secrets)
npm start                                                # http://localhost:3003/health
```
Merging needs the roadmap and engagement services running. For the whole system, use `roadhub-frontend`.

## Tests
```bash
npm test
```
Starts this service as its own process with its real tables, plus a **fake roadmap service** and a **fake
engagement service**, so it needs only Floci and the tables.
- `tests/auth.test.js`: sign-up (role cannot be chosen, weak password, duplicate e-mail, 3 sign-ups at once),
  login (same message for unknown e-mail and wrong password, lockout → 423), forged tokens, logout, internal endpoints and scopes.
- `tests/admin.test.js`: admin-only access, suspend/restore/ban (old tokens stop, banned login refused, audit),
  duplicate suggestions, the merge saga (step order, one request id, Idempotency-Key, scopes), compensation when
  engagement fails half-way (FAILED, 503, no leaked error text), a 409 from roadmap, undo and second undo, security events.

## Folders
`routes/` → `controllers/` → `services/` (business rules: auth, tokens, merge saga, moderation) → `repositories/`
(DynamoDB). `scripts/create-admin.js` makes the first admin, `shared/` is the common kit (identical in the three
service repos, see `shared/README.md`), `infra/` holds the Floci scripts, `tests/` the tests.
