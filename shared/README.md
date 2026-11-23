# shared/: the common kit (same files in all three service repos)

These helpers are used by every RoadmapHub backend. Each service repo keeps its **own copy**, so it
installs, runs and deploys on its own, with no link to another repository.

| File | What it does |
|---|---|
| `http.js` | error format `{error:{code,message,details}}`, request id, request log, security headers |
| `logger.js` | one JSON log line per event |
| `secrets.js` | reads secrets from AWS Secrets Manager (names only in code, never values) |
| `user-auth.js` | checks user logins (RS256 JWT + account state) |
| `remote-status.js` | asks the Administration Service for an account's state |
| `internal-auth.js` | service-to-service tokens (HS256, 60 s, audience + scope) |
| `internal-client.js` | HTTP client between services: timeout, retries, request id, idempotency key |
| `dynamo.js`, `storage.js`, `cursor.js` | DynamoDB client, `STORAGE_DRIVER` choice, page cursors |
| `validate.js`, `rate-limit.js`, `turnstile.js`, `events.js` | input checks, rate limits, bot check, EventBridge publishing |

**Rule:** the three copies must stay identical (version 1.0.0, from the team baseline). A change here
changes the team contract: open a PR in **all three** service repos with the same change, and get the
other owners' approval. Never change one copy alone.
