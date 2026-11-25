# Security & Monitoring Evidence — `roadhub-admin-service` (S3)

- **Owner:** Joseph Maged Aziz (240028) · Team 22 (Lab Group A-3)
- **Generated:** 2026-11-25T19:14:08.501Z
- **Environment:** Real Floci (`http://127.0.0.1:4566`), Node.js v26.13.1
- **Summary:** **12 / 12 PASS** (0 failed)

---

## 1. Controlled Security Test Table (Final Report Section 12)

| Test ID | Category | Scenario | Expected Result | Actual Result | Pass/Fail | Evidence (Observed Response / Scan) |
|---|---|---|---|---|---|---|
| ST-01 | Unauthenticated access | GET /api/admin/users without Authorization header | 401 UNAUTHENTICATED | 401 UNAUTHENTICATED | **PASS** | `HTTP 401 {"error":{"code":"UNAUTHENTICATED","message":"Please log in first."}}` |
| ST-02 | Unauthorized role (RBAC) | Standard user calls GET /api/admin/users and POST /api/admin/features/:id/merge | 403 FORBIDDEN on both | 403 FORBIDDEN; merge 403 FORBIDDEN | **PASS** | `HTTP 403 {"error":{"code":"FORBIDDEN","message":"Your role is not allowed to do this."}}` |
| ST-03 | Invalid input (mass assignment) | POST /api/auth/register includes extra field role="admin" | 400 VALIDATION_ERROR (role rejected) | 400 VALIDATION_ERROR | **PASS** | `HTTP 400 {"error":{"code":"VALIDATION_ERROR","message":"Unexpected field(s): role.","details":{"fields":["role"]}}}` |
| ST-04 | Invalid input & media type | Weak password ("short1") on signup + text/plain body on login | 400 VALIDATION_ERROR and 415 UNSUPPORTED_MEDIA_TYPE | 400 VALIDATION_ERROR; 415 UNSUPPORTED_MEDIA_TYPE | **PASS** | `Signup: 400 {"error":{"code":"VALIDATION_ERROR","message":"password must contain between 10 and 128 characters.","details":{"field":"password"}}}; Login: 415 {"error":{"code":"UNSUPPORTED_MEDIA_TYPE","message":"Content-Type must be application/json."}}` |
| ST-05 | Token forgery & alg:none | GET /api/auth/me with attacker-signed RS256 JWT and alg="none" JWT | 401 UNAUTHENTICATED on both | forged 401; alg:none 401 | **PASS** | `HTTP 401 {"error":{"code":"UNAUTHENTICATED","message":"Your session is not valid. Please log in again."}}` |
| ST-06 | Brute-force lockout & anti-enumeration | Unknown vs wrong password produce same 401; 5 failed logins trigger lockout | Identical 401 message + 423 ACCOUNT_LOCKED on 6th attempt | same401=true; 6th=423 ACCOUNT_LOCKED | **PASS** | `HTTP 423 {"error":{"code":"ACCOUNT_LOCKED","message":"Too many failed attempts. Try again in 15 minutes."}}` |
| ST-07 | Access/ownership guardrails & revocation | Admin self-ban + banning another admin blocked; logout invalidates old JWT immediately | 403 CANNOT_TARGET_SELF, 403 CANNOT_TARGET_ADMIN, 204 logout -> 401 old JWT | self=403 CANNOT_TARGET_SELF; admin=403 CANNOT_TARGET_ADMIN; postLogout=401 | **PASS** | `Self: {"error":{"code":"CANNOT_TARGET_SELF","message":"You cannot change your own account."}}; Admin: {"error":{"code":"CANNOT_TARGET_ADMIN","message":"Administrators cannot be suspended or banned here."}}; Old token: HTTP 401` |
| ST-08 | External API bot check (Turnstile) | POST /api/auth/register with TURNSTILE_ENABLED=true and no X-Turnstile-Token | 403 BOT_CHECK_FAILED | 403 BOT_CHECK_FAILED | **PASS** | `HTTP 403 {"error":{"code":"BOT_CHECK_FAILED","message":"Please complete the bot check and try again."}}` |
| ST-09 | Internal service token & scope check | User JWT sent to /internal/identity/*; identity:read scope calls /contacts | 401 UNAUTHENTICATED and 403 SCOPE_MISSING | userJwt=401; wrongScope=403 SCOPE_MISSING | **PASS** | `UserJWT: HTTP 401; Scope: HTTP 403 {"error":{"code":"SCOPE_MISSING","message":"This call needs the scope identity:contacts."}}` |
| ST-10 | SNS webhook topic & SSRF check | POST /internal/alerts/sns with rogue TopicArn and untrusted SigningCertURL | 403 SNS_TOPIC_MISMATCH and 403 SNS_CERT_URL_INVALID | topic=403 SNS_TOPIC_MISMATCH; cert=403 SNS_CERT_URL_INVALID | **PASS** | `Topic: {"error":{"code":"SNS_TOPIC_MISMATCH","message":"SNS notifications from this topic are not accepted."}}; Cert: {"error":{"code":"SNS_CERT_URL_INVALID","message":"SNS SigningCertURL is not from a trusted SNS host."}}` |
| ST-11 | Security headers & rate limiting | Verify 5 security headers, no X-Powered-By, and 11 rapid login requests trigger 429 | All 5 headers present + 429 RATE_LIMITED with Retry-After | headers=true; 11th=429 RATE_LIMITED (Retry-After: 60s) | **PASS** | `Headers OK; HTTP 429 Retry-After=60 {"error":{"code":"RATE_LIMITED","message":"Too many requests. Please wait and try again."}}` |
| ST-12 | Secret exposure & IAM review | Scan all Git tracked files for secrets/.env, check IAM zero-wildcard policy, check CloudWatch Logs for leaked passwords/JWTs | 0 secret files, 0 secret patterns, 0 IAM wildcards, 0 secrets in CloudWatch Logs | tracked=72, forbiddenFiles=0, secretHits=0, iamWildcard=false, cwLeaks=false | **PASS** | `Git: 0/.env & 0 secrets across 72 files; IAM: 5 statements, 0 wildcards; CW Logs: 0 passwords/JWTs across 100 events` |

---

## 2. CloudWatch Logs & Security Monitoring Evidence (Final Report Section 11)

### 2.1 Live Floci CloudWatch Logs (`/roadhub/admin` → `admin-service`)
Captured directly from Floci during this controlled run (demonstrating `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `ACCESS_DENIED`, `RATE_LIMITED`, and `SNS_TOPIC_MISMATCH` with **zero** plaintext passwords, tokens, or secrets):

```json
{"time":"2026-11-25T19:14:02.546Z","level":"SECURITY","service":"admin","event":"AUTH_FAILED","requestId":"sec-st01-94ab0fdf","method":"GET","path":"/api/admin/users","code":"UNAUTHENTICATED","ip":"::ffff:127.0.0.1"}
{"time":"2026-11-25T19:14:02.556Z","level":"SECURITY","service":"admin","event":"ACCESS_DENIED","requestId":"sec-st02-94ab0fdf","method":"GET","path":"/api/admin/users","code":"FORBIDDEN","userId":"d277b6b7-a7c9-49f5-85a3-9cf09b499ca1","ip":"::ffff:127.0.0.1"}
{"time":"2026-11-25T19:14:02.758Z","level":"SECURITY","service":"admin","event":"LOGIN_FAILED","requestId":"sec-st06u-94ab0fdf","ip":"::ffff:127.0.0.1"}
{"time":"2026-11-25T19:14:02.770Z","level":"SECURITY","service":"admin","event":"AUTH_FAILED","requestId":"sec-st06u-94ab0fdf","method":"POST","path":"/api/auth/login","code":"UNAUTHENTICATED","ip":"::ffff:127.0.0.1"}
{"time":"2026-11-25T19:14:02.834Z","level":"SECURITY","service":"admin","event":"LOGIN_FAILED","requestId":"sec-st06-0-94ab0fdf","ip":"::ffff:127.0.0.1","userId":"f627dc9a-a994-4f2d-b127-5d2fda3b92d7"}
{"time":"2026-11-25T19:14:02.859Z","level":"SECURITY","service":"admin","event":"AUTH_FAILED","requestId":"sec-st06-0-94ab0fdf","method":"POST","path":"/api/auth/login","code":"UNAUTHENTICATED","ip":"::ffff:127.0.0.1"}
{"time":"2026-11-25T19:14:02.923Z","level":"SECURITY","service":"admin","event":"LOGIN_FAILED","requestId":"sec-st06-1-94ab0fdf","ip":"::ffff:127.0.0.1","userId":"f627dc9a-a994-4f2d-b127-5d2fda3b92d7"}
{"time":"2026-11-25T19:14:02.949Z","level":"SECURITY","service":"admin","event":"AUTH_FAILED","requestId":"sec-st06-1-94ab0fdf","method":"POST","path":"/api/auth/login","code":"UNAUTHENTICATED","ip":"::ffff:127.0.0.1"}
```

### 2.2 CloudWatch Metric Filters on `/roadhub/admin`

| Filter Name | Filter Pattern | Metric Namespace | Metric Name | Value |
|---|---|---|---|---|
| `roadhub-admin-access-denied` | `{ $.level = "SECURITY" && ($.event = "ACCESS_DENIED" || $.event = "AUTH_FAILED") }` | `RoadHub/Admin` | `AccessDeniedCount` | `1` |
| `roadhub-admin-failed-logins` | `{ $.level = "SECURITY" && $.event = "LOGIN_FAILED" }` | `RoadHub/Admin` | `FailedLoginCount` | `1` |

### 2.3 CloudWatch Brute-Force Alarm → SNS

```json
[
  {
    "AlarmName": "roadhub-admin-brute-force-alarm",
    "Namespace": "RoadHub/Admin",
    "MetricName": "FailedLoginCount",
    "Statistic": "Sum",
    "PeriodSeconds": 300,
    "Threshold": 5,
    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
    "AlarmActions": [
      "arn:aws:sns:us-east-1:000000000000:roadhub-ops-alerts"
    ]
  }
]
```

### 2.4 Admin Security Events Endpoint (`GET /api/admin/security-events?minutes=15`)

```json
{
  "windowMinutes": 15,
  "totalEvents": 17,
  "alerts": 1,
  "sources": [
    {
      "ip": "::ffff:127.0.0.1",
      "total": 17,
      "byAction": {
        "LOGIN_FAILED": 16,
        "ACCOUNT_LOCKED": 1
      },
      "failedLoginsLast15Min": 16,
      "alert": true
    }
  ]
}
```
