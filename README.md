# AuthAPI

A standalone, **multi-tenant** authentication service written in Go. Issues short-lived RSA-signed JWT access tokens and long-lived rotating refresh tokens, with email verification, password reset, Redis-backed brute-force protection, refresh-token-reuse detection, and event publishing for downstream consumers (such as the companion email microservice).

## Features

- **Multi-tenancy** — every request to the public auth endpoints is scoped to a tenant via the `X-Tenant` header. Users are unique per `(tenant_id, email)`, and the tenant is resolved (and checked for `active` status) before any handler runs
- **Signup / Login** — bcrypt (cost 12) password hashing, email verification with resend support, constant-time-ish login failure path (a dummy hash is compared for unknown users)
- **Password management** — change password, request a reset email, and reset with a one-time token
- **JWT access tokens** — RS256-signed, 15-minute lifetime, verified via a public key so downstream services can validate tokens without calling back into AuthAPI
- **Refresh token rotation** — each refresh issues a new token and revokes the old one; **reuse of an already-rotated token revokes the entire token family**, following the OAuth 2.0 Security BCP refresh token rotation pattern. Refresh tokens last 30 days and are stored as HMAC-SHA256 hashes (keyed with `TOKEN_SECRET`), never in plaintext
- **Redis-backed rate limiting & lockout** — Lua scripts run atomically in Redis to throttle login, signup, and password-reset-request attempts per IP, per account, and per IP+account pair. Repeated login failures trigger escalating cool-downs and a "suspicious activity" event (see Rate limiting section)
- **Outbox pattern** — domain events (user created, email verification requested, password reset requested, login events, …) are written transactionally alongside application state and published to RabbitMQ by a background worker, with publisher confirms, exponential backoff, and multi-worker-safe row claiming
- **Structured logging** — JSON logs in production, colorized human-readable logs in development, via `log/slog`
- **Request correlation IDs** — every request gets an `X-Request-ID` (UUIDv7 if not supplied), propagated through logs for tracing
- **Prometheus metrics** — HTTP request counts/latency, login/signup outcomes, refresh-reuse detections, exposed at `/metrics`
- **Swagger / OpenAPI docs** — served at `/auth/swagger/*`
- **Dual database support** — PostgreSQL (recommended for production) or SQLite (deprecated, local development only)
- **Containerized** — `docker-compose.yml` brings up PostgreSQL, Redis, the AuthAPI container, and the email microservice
- **Automated tests & CI** — unit, repository, and end-to-end tests (PostgreSQL via testcontainers), run with lint on every push/PR via GitHub Actions

## Tech stack

|||
|---|---|
|Language|Go 1.26|
|Router|[chi](https://github.com/go-chi/chi) (+ `go-chi/cors`)|
|Database|PostgreSQL 16 or SQLite (`pgx`, `mattn/go-sqlite3`)|
|Cache / rate limiting|Redis 8 (`go-redis` v9, embedded Lua scripts)|
|Messaging|RabbitMQ (outbox pattern, topic exchange, publisher confirms)|
|Auth|RS256 JWT (`golang-jwt/jwt` v5), bcrypt, HMAC-SHA256 token hashing|
|Metrics|Prometheus (`client_golang`)|
|Docs|swaggo|
|Testing|`go test`, testcontainers-go (PostgreSQL)|
|CI|GitHub Actions + golangci-lint|

## Getting started

### Prerequisites

- Go 1.26+
- **Redis** (required — the service pings Redis at startup and will not boot without it)
- SMTP credentials (the config loader requires `SMTP_HOST`, `SMTP_USER`, `SMTP_APP_PASSWORD`, and `SMTP_FROM`, internal SMTP is deprecated and is in process of removal)
- PostgreSQL 
- RabbitMQ (only used with the `postgres` driver — see Outbox / messaging section)
- Docker (optional, for `docker compose` and for running the Postgres-backed tests)

### 1. Clone and configure

```bash
git clone <repo-url>
cd AuthAPI
cp .env.example .env
```

Fill in `.env` — see Configuration below for what each variable does.

### 2. Generate RSA signing keys

The service signs access tokens with RS256 and needs a keypair on disk (paths configurable via env):

```bash
mkdir -p creds
openssl genrsa -out creds/private.pem 2048
openssl rsa -in creds/private.pem -pubout -out creds/public.pem
```

> ⚠️ Never commit `creds/` or `.env` to version control. Keep them in `.gitignore` and rotate these keys if they're ever exposed.

Key lookup order is: the `AUTH_PRIVATE_KEY_PATH` / `AUTH_PUBLIC_KEY_PATH` env vars → Docker secrets at `/run/secrets/authapi_private_key` / `authapi_public_key` → `creds/private.pem` / `creds/public.pem`.

### 3. Provision a tenant

Every public endpoint requires an `X-Tenant` header that matches an **active** row in the `tenants` table. There is currently no API for creating tenants (see Roadmap section), so insert one directly after the first startup. A commented-out example is included at the bottom of the tenants section in `migrations/postgres/001_init.sql`:

```sql
INSERT INTO tenants (
    tenant_id, tenant_name, name, url, email, status,
    public_key, api_key_hash, allowed_origins, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000001', 'acme', 'Acme Inc.',
    'https://acme.com', 'admin@acme.com', 'active',
    'test-public-key', 'test-api-key-hash', '["https://acme.com"]'::jsonb, NOW(), NOW()
);
```

### 4. Database migrations

Migrations live under `migrations/postgres/` and `migrations/sqlite/` and run automatically on startup based on the configured driver.

### 5. Run it

**Locally:**

```bash
go run ./cmd/server
```

**With Docker Compose:**

```bash
docker compose up -d
```

Compose starts PostgreSQL (host port `5433`), Redis (host port `6380`), the AuthAPI container, and the [email microservice](https://github.com/Fletcher17b/EmailMicroService). It expects:

- `.env.compose` — environment for the `authapi` container
- `.env.mailservice` — environment for the email service
- `./creds/private.pem` and `./creds/public.pem` — mounted as Docker secrets
- Pre-existing external Docker networks: `api-gateway` and `rabbitmq-network` (`docker network create <name>`), plus a RabbitMQ instance reachable on `rabbitmq-network`

The AuthAPI container only `expose`s port `8081` on the internal networks; it's designed to sit behind an API gateway rather than be published directly.

The service listens on `:8081`.

## Configuration

All configuration is via environment variables (see `.env.example` for a starting point). Key ones:

| Variable                                                                    | Description                                                                                                 | Default                              |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `APP_ENV`                                                                   | `development`, `production`, or `test` — controls log format (colorized text vs. JSON)                      | **required**                         |
| `LOG_LEVEL`                                                                 | Minimum log severity: `debug`, `info`, `warn`, `error`                                                      | **required**                         |
| `APP_BASE_URL`                                                              | Base URL used in generated links (e.g. email verification)                                                  | **required**                         |
| `CORS_ALLOWED_ORIGINS`                                                      | Comma-separated list of allowed CORS origins (if empty, all origins are allowed _without_ credentials)      | —                                    |
| `DB_DRIVER`                                                                 | `postgres` or `sqlite`                                                                                      | `sqlite`                             |
| `PSQL_HOST` / `PSQL_PORT` / `PSQL_USER` / `PSQL_PASSWORD` / `PSQL_DATABASE` | PostgreSQL connection settings. If any are missing, the service logs a warning and **falls back to SQLite** | —                                    |
| `SQLITE_PATH`                                                               | SQLite file path                                                                                            | `auth.db`                            |
| `REDIS_ADDR`                                                                | Redis address, e.g. `localhost:6379`                                                                        | **required**                         |
| `REDIS_PROTOCOL`                                                            | Redis protocol version (e.g. `3`)                                                                           | **required**                         |
| `REDIS_DB`                                                                  | Redis database index                                                                                        | **required**                         |
| `TOKEN_SECRET`                                                              | Secret used to HMAC-hash refresh/verification/reset tokens and sign client IDs                              | **required**                         |
| `AUTH_PRIVATE_KEY_PATH` / `AUTH_PUBLIC_KEY_PATH`                            | RSA key locations                                                                                           | `creds/*.pem`                        |
| `RABBITMQ_URL`                                                              | RabbitMQ connection URL (only used with the `postgres` driver)                                              | `amqp://guest:guest@localhost:5672/` |
| `RABBITMQ_EXCHANGE`                                                         | Topic exchange events are published to                                                                      | `authapi.events`                     |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_APP_PASSWORD` / `SMTP_FROM` | SMTP settings (deprecated, removal in progress)                                                             | —                                    |

## API

All routes are mounted under the `/auth` prefix. Interactive API documentation is served at:

```
GET /auth/swagger/*
```

### Headers

|Header|Applies to|Description|
|---|---|---|
|`X-Tenant`|Public endpoints (signup, login, refresh, logout, verification, password flows)|Tenant identifier. Missing → `400`, unknown → `401`, inactive → `403`|
|`Authorization: Bearer <access_token>`|`/auth/me`, `/auth/revoke-all`|RS256 access token|
|`X-Request-ID`|All|Optional; generated if absent and echoed back on the response|

### Endpoints

|Method|Path|Auth|Description|
|---|---|---|---|
|POST|`/auth/signup`|Tenant|Creates a user, sends a verification email, publishes outbox events|
|POST|`/auth/login`|Tenant · rate-limited|Authenticates with email/password, returns access + refresh tokens|
|POST|`/auth/refresh`|Tenant (refresh token)|Rotates a refresh token, returns a new token pair|
|POST|`/auth/logout`|Tenant (refresh token)|Revokes a refresh token|
|GET|`/auth/verify-email`|Tenant (verification token)|Confirms a user's email address|
|POST|`/auth/resend-verification`|Tenant|Re-sends the verification email|
|POST|`/auth/password-change`|Tenant|Changes the password (requires current password; new password must differ)|
|GET|`/auth/send-resetemail`|Tenant · rate-limited|Requests a password reset email|
|POST|`/auth/reset-password`|Tenant (reset token)|Sets a new password using a reset token|
|GET|`/auth/me`|**JWT**|Returns the authenticated user's identity|
|POST|`/auth/revoke-all`|**JWT**|Revokes all refresh tokens for the authenticated user|
|GET|`/auth/health`|None|Liveness/readiness check (verifies DB connectivity)|
|GET|`/auth/swagger/*`|None|Swagger UI|
|GET|`/metrics`|None|Prometheus metrics endpoint|

> `/register` (the old minimal signup path) is no longer routed; use `/auth/signup`.

Requests are limited to 1 MiB, and handlers reject unknown JSON fields.

### Access token claims

Access tokens are RS256-signed with `iss: auth-service`, `sub` = user ID, plus `userid` and `email` claims, and expire after 15 minutes. Downstream services only need the public key to validate them.

## Rate limiting

Rate limiting is enforced by `RateLimitMiddleware` using atomic Redis Lua scripts (`internal/auth/luascripts/`). Counters are keyed per IP, per account (email), and per IP+account pair.

|Endpoint|Behaviour|
|---|---|
|`POST /auth/login`|Failures are counted per IP, account, and pair. From the 6th failure, attempts are blocked for 5 minutes; from the 11th, for 1 hour. On the 5th failure a `suspicious login` event is queued for the user. Blocked requests get `429`|
|`POST /auth/signup`|Per-IP attempt throttling|
|`GET /auth/send-resetemail`|Per-IP and per-account throttling to prevent reset-email spam|

If Redis errors out during a check, the failure is logged and the request is allowed through (fail-open). Per-tenant, configurable rate policies are modelled but not yet implemented (see Roadmap section).

## Refresh token reuse detection

Refresh tokens are grouped into **families**. Every successful `/auth/refresh` call revokes the presented token and issues a new one in the same family. If a token that has _already_ been rotated is presented again — meaning it was either replayed by an attacker or used twice by mistake — the **entire family is revoked**, invalidating that whole session chain rather than just the one token. This limits the blast radius of a leaked refresh token without requiring IP binding, which is unreliable across mobile networks, VPNs, and NAT. Reuse is surfaced via the `authapi_refresh_reuse_detected_total` metric.

## Outbox / messaging

Domain events are written to an `outbox_events` table in the same transaction as the triggering state change, then asynchronously published to a durable RabbitMQ **topic exchange** by a background worker (`internal/outbox`). This avoids dual-write inconsistency between the database and the message broker.

Events currently emitted include `user.created`, `email.verification.requested`, `email.password_reset.requested`, `user.login.succeeded`, and `user.login.failed`. Each envelope carries an `event_id`, `event_type`, payload, and headers, and email-related payloads include the tenant name so consumers can render per-tenant messages.

The worker:

- polls every 5 seconds in batches of 50
- **claims** rows (`status=processing`, with `locked_by` / `locked_until`) so multiple instances can run safely, and reclaims rows abandoned by a crashed worker after 30 seconds
- waits for **RabbitMQ publisher confirms** before marking an event `published`
- retries failures with exponential backoff (2s base, 5 min cap, up to 8 retries)

AuthAPI only declares and publishes to the exchange; consumers (e.g. the email microservice) declare and bind their own queues.

> RabbitMQ publishing is only wired up when running with the `postgres` driver. When developing locally against SQLite, outbox events are written but not published. Running SQLite with `APP_ENV=production` logs a warning at startup.

## Observability

- **Logs** — structured via `log/slog`. In development, output is short and color-coded (`INFO` green, `WARN` yellow, `ERROR` red, `DEBUG` gray); in production, output is raw JSON suitable for log aggregation. Panics are recovered, logged with a stack trace and request ID, and returned as a JSON `500`
- **Metrics** — Prometheus format at `GET /metrics`, including:
    - `authapi_http_requests_total{route,method,status}`
    - `authapi_http_request_duration_seconds{route,method}`
    - `authapi_login_attempts_total{result}`
    - `authapi_signups_total{result}`
    - `authapi_refresh_reuse_detected_total`
- **Request correlation** — every request is tagged with an `X-Request-ID` (respected if the caller/gateway already sets one), propagated into logs for tracing a request end-to-end
- **Health check** — `GET /auth/health` verifies database connectivity, suitable for liveness/readiness probes

## Testing

```bash
go test ./...
```

The suite covers JWT handling, handlers and services, config/key loading, password/token hashing, and the user, refresh-token, and outbox repositories, plus end-to-end tests under `internal/tests`. Postgres-backed tests spin up a throwaway `postgres:16-alpine` container using testcontainers, so **Docker must be running** (tests that need it are skipped/fail with a clear reason otherwise).

### CI

`.github/workflows/go-ci.yml` runs on pushes and pull requests to `main`. It generates disposable RSA keys, writes CI env files from repository secrets (`CI_SMTP_HOST`, `CI_SMTP_USER`, `CI_SMTP_APP_PASSWORD`, `CI_TOKEN_SECRET`), starts the dependent services, then runs `golangci-lint` and `go test ./...`.

## Project layout

```
cmd/server/                entrypoint, wiring, graceful shutdown
internal/auth/             handlers, service logic, JWT, middleware, errors
internal/auth/app/         shared application dependency struct
internal/auth/refresh/     refresh token repository (postgres/sqlite)
internal/auth/mail/        email verification repository + SMTP
internal/auth/metrics/     Prometheus instrumentation
internal/auth/ratelimiter/ Redis-backed limiter
internal/auth/luascripts/  embedded Lua scripts for atomic rate-limit checks
internal/auth/tenants/     tenant repository (postgres/sqlite)
internal/auth/logger/      slog setup (JSON / dev-colorized)
internal/auth/auth_tests/  handler and service tests
internal/broker/           RabbitMQ client (topic exchange, publisher confirms)
internal/config/           env loading, router setup, key loading
internal/crypto/           bcrypt + HMAC token hashing
internal/db/               migrations, connection setup
internal/models/           shared domain types (users, tenants, tokens, events)
internal/outbox/           outbox pattern (event write, claim, async publish)
internal/users/            user repository (postgres/sqlite)
internal/tests/            end-to-end tests and test DB helpers
migrations/                SQL migrations per driver
docker-compose.yml         postgres, redis, authapi, email microservice
.github/workflows/         CI pipeline
```

## Roadmap / known gaps

- [x] Automated tests (unit, repository, and end-to-end) and CI
- [x] Redis-backed brute-force protection for login, signup, and reset requests
- [x] Password change / reset flow
- [x] Multi-tenant request scoping
- [ ] Tenant provisioning API (tenants are currently inserted via SQL; the repository is read-only)
- [ ] Per-tenant policies (notification and rate-limit policies are modelled in `internal/models/tenant_policies.go` but have no schema or wiring yet)
- [ ] Tenant-aware CORS (`allowed_origins` is stored per tenant but CORS currently uses the global `CORS_ALLOWED_ORIGINS`)
- [ ] New-device login notification emails (event type and payload exist; not yet enabled)
- [ ] OAuth / social login (`oauth_identities` table exists; no flows yet)
- [ ] Scheduled cleanup of expired/revoked refresh tokens
- [ ] Swagger annotations are out of sync with the actual `/auth/*` routes and need regenerating
- [ ] SQLite-mode fallback for Redis (Redis is currently required even for local development)

## License

No license