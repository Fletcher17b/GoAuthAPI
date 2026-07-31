# AuthAPI

A standalone authentication service written in Go. Issues short-lived RSA-signed JWT access tokens and long-lived rotating refresh tokens, with email verification, refresh-token-reuse detection, and event publishing for downstream consumers.

## Features

- **Signup / Login** — password hashing via bcrypt, email verification flow with resend support
- **JWT access tokens** — RS256-signed, short-lived, verified via a public key so downstream services can validate tokens without calling back into AuthAPI
- **Refresh token rotation** — each refresh issues a new token and revokes the old one; **reuse of an already-rotated token revokes the entire token family**, following the [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) refresh token rotation pattern
- **Outbox pattern** — domain events (e.g. user signed up) are written transactionally alongside application state and published to RabbitMQ by a background worker, so downstream services stay eventually consistent without dual-write issues
- **Structured logging** — JSON logs in production, colorized human-readable logs in development, via `log/slog`
- **Request correlation IDs** — every request gets an `X-Request-ID`, propagated through logs for tracing
- **Prometheus metrics** — HTTP request counts/latency, login/signup outcomes, refresh-reuse detections, exposed at `/metrics`
- **Swagger / OpenAPI docs** — served at `/swagger/*`
- **Dual database support** — PostgreSQL (recommended for production) or SQLite (recommended for local development)

## Tech stack

| | |
|---|---|
| Language | Go 1.26 |
| Router | [chi](https://github.com/go-chi/chi) |
| Database | PostgreSQL or SQLite |
| Messaging | RabbitMQ (outbox pattern) |
| Auth | RS256 JWT (`golang-jwt/jwt`), bcrypt |
| Metrics | Prometheus (`client_golang`) |
| Docs | swaggo |

## Getting started

### Prerequisites

- Go 1.26+
- PostgreSQL (or use the bundled SQLite driver for local dev)
- RabbitMQ (only required when running with the `postgres` driver — see [Outbox / messaging](#outbox--messaging))

### 1. Clone and configure

```bash
git clone <repo-url>
cd AuthAPI
cp .env.example .env
```

Fill in `.env` — see [Configuration](#configuration) below for what each variable does.

### 2. Generate RSA signing keys

The service signs access tokens with RS256 and needs a keypair on disk (paths configurable via env):

```bash
mkdir -p creds
openssl genrsa -out creds/private.pem 2048
openssl rsa -in creds/private.pem -pubout -out creds/public.pem
```

> ⚠️ Never commit `creds/` or `.env` to version control. Both are already covered by `.gitignore` — keep it that way, and rotate these keys if they're ever exposed.

### 3. Run database migrations

Migrations live under `migrations/postgres/` and `migrations/sqlite/` and run automatically on startup based on the configured driver.

### 4. Run it

```bash
go run ./cmd/server
```

The service listens on `:8081` by default.

## Configuration

All configuration is via environment variables (see `.env.example` for the full list). Key ones:

| Variable | Description | Default |
|---|---|---|
| `APP_ENV` | `development` or `production` — controls log format (colorized text vs. JSON) | `development` |
| `LOG_LEVEL` | Minimum log severity: `debug`, `info`, `warn`, `error` | `info` |
| `APP_BASE_URL` | Base URL used in generated links (e.g. email verification) | — |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | — |
| `DB_DRIVER` | `postgres` or `sqlite` | — |
| `DATABASE_URL` / SQLite path | Connection string or file path, depending on driver | — |
| `BROKER_URL` | RabbitMQ connection URL (only used with `postgres` driver) | — |
| `SMTP_*` | SMTP credentials for sending verification emails | — |

## API

Interactive API documentation is served at:

```
GET /swagger/*
```

### Endpoints

| Method | Path | Auth required | Description |
|---|---|---|---|
| POST | `/register` | No | Minimal signup path (primarily for local testing) |
| POST | `/signup` | No | Full signup flow — creates user, sends verification email, publishes outbox event |
| POST | `/login` | No | Authenticate with email/password, returns access + refresh tokens |
| POST | `/refresh` | No (refresh token) | Rotates a refresh token, returns a new token pair |
| POST | `/logout` | No (refresh token) | Revokes a refresh token |
| GET | `/verify-email` | No (verification token) | Confirms a user's email address |
| POST | `/resend-verification` | No | Re-sends the verification email |
| GET | `/me` | **Yes (JWT)** | Returns the authenticated user's identity |
| POST | `/revoke-all` | **Yes (JWT)** | Revokes all refresh tokens for the authenticated user |
| GET | `/health` | No | Liveness/readiness check (verifies DB connectivity) |
| GET | `/metrics` | No | Prometheus metrics endpoint |

Authenticated endpoints expect:
```
Authorization: Bearer <access_token>
```

## Refresh token reuse detection

Refresh tokens are grouped into **families**. Every successful `/refresh` call revokes the presented token and issues a new one in the same family. If a token that has *already* been rotated is presented again — meaning it was either replayed by an attacker or used twice by mistake — the **entire family is revoked**, invalidating that whole session chain rather than just the one token. This limits the blast radius of a leaked refresh token without requiring IP binding, which is unreliable across mobile networks, VPNs, and NAT.

## Outbox / messaging

Domain events (e.g. `user.signed_up`) are written to an `outbox` table in the same transaction as the triggering state change, then asynchronously published to RabbitMQ by a background worker (`internal/outbox`). This avoids dual-write inconsistency between the database and the message broker.

> RabbitMQ publishing is currently only wired up when running with the `postgres` driver. When developing locally against SQLite, outbox events are written but not published.

## Observability

- **Logs** — structured via `log/slog`. In development, output is short and color-coded (`INFO` green, `WARN` yellow, `ERROR` red, `DEBUG` gray); in production, output is raw JSON suitable for log aggregation.
- **Metrics** — Prometheus format at `GET /metrics`, including:
  - `authapi_http_requests_total{route,method,status}`
  - `authapi_http_request_duration_seconds{route,method}`
  - `authapi_login_attempts_total{result}`
  - `authapi_signups_total{result}`
  - `authapi_refresh_reuse_detected_total`
- **Request correlation** — every request is tagged with an `X-Request-ID` (respected if the caller/gateway already sets one), propagated into logs for tracing a request end-to-end.
- **Health check** — `GET /health` verifies database connectivity, suitable for liveness/readiness probes.

## Project layout

```
cmd/server/          entrypoint
internal/auth/        handlers, service logic, JWT, middleware
internal/auth/refresh/ refresh token repository (postgres/sqlite)
internal/auth/mail/    email verification + SMTP
internal/auth/metrics/ Prometheus instrumentation
internal/broker/       RabbitMQ client
internal/config/       env loading, router setup, key loading
internal/db/           migrations, connection setup
internal/models/       shared domain types
internal/outbox/       outbox pattern (event write + async publish)
internal/users/        user repository (postgres/sqlite)
migrations/            SQL migrations per driver
```

## Roadmap / known gaps

- [ ] Automated tests (unit + integration)
- [ ] Redis-backed account lockout / brute-force protection
- [ ] Scheduled cleanup of expired/revoked refresh tokens
- [ ] Full Swagger annotation coverage on all handlers
- [ ] Password reset flow (schema exists, not yet wired up)

## License

_Add a license._