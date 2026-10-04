# duongondro-api

The Go backend for [Duongöndro](https://duongondro.app): track your meditation practice together with your friends, end-to-end encrypted and fully open source.

The server stores sealed blobs and signed public streaks. It never receives a practice count, a round number or a key: see [docs/crypto.md](docs/crypto.md).

## What is here

| Path | Contents |
| --- | --- |
| `api/openapi.yaml` | The HTTP contract; handlers follow it by hand and a test checks every operation is routed |
| `docs/crypto.md` | Byte formats for sealed sessions, wraps, signed statements, invites, recovery |
| `docs/streaks.md` | The streak rules, including the jet-lag deadline |
| `docs/stack.md` | Where the stack deviates from CodeShare's, and what is left to build |
| `testdata/vectors.json` | Crypto test vectors for the iOS and Android clients |
| `testdata/streak-cases.json` | Streak conformance cases every implementation must pass |
| `internal/e2ee` | Reference implementation of the crypto formats |
| `internal/streak` | Reference implementation of the streak rules |
| `internal/db` | Embedded SQL migrations and the runner; `dbtest` gives each test a private schema |
| `internal/store` | Repository layer: hand-written SQL |
| `internal/server` | HTTP handlers, sessions, rate limits |
| `internal/push` | APNs and FCM payload builders (localisation keys only) |
| `internal/ids` | UUIDv7, invite ids, bearer tokens |
| `internal/web`, `web/` | The public website, served at `/` |
| `cmd/duongondro-api` | The server binary |

## Endpoints

All API routes are under `/api/`; everything else is the website. Authenticated routes take `Authorization: Bearer <token>`.

| Area | Routes |
| --- | --- |
| Meta | `GET /healthz`, `GET /api/version` |
| Sign-in | `POST /api/auth/magic-link`, `POST /api/auth/magic-link/verify`, `DELETE /api/me/session` |
| Account | `GET /api/me`, `PATCH /api/me`, `GET /api/me/export`, `DELETE /api/me`, `PUT /api/me/key-version` |
| Devices and keys | `GET`/`POST /api/devices`, `DELETE /api/devices/{deviceId}`, `PUT /api/device-list`, `GET /api/users/{userId}/device-list`, `GET`/`PUT /api/wraps`, `GET /api/recovery-boxes`, `PUT /api/recovery-boxes/{kind}` |
| Sync | `PUT /api/practice-logs/{logId}`, `GET /api/sync?since=<generation>:<xid8>` |
| Invites | `GET`/`POST /api/invites`, `GET`/`DELETE /api/invites/{inviteId}`, `POST /api/invites/{inviteId}/redeem`, `GET /api/invites/{inviteId}/redemptions` |
| Friends and streaks | `GET /api/friends`, `DELETE /api/friends/{userId}`, `GET /api/friends/streaks`, `PUT /api/streaks`, `DELETE /api/streaks/{practice}` |
| Moderation | `GET /api/blocks`, `PUT`/`DELETE /api/blocks/{userId}`, `POST /api/reports` |
| Push | `PUT`/`DELETE /api/push-tokens`, `POST /api/nudges/poke/{friendId}` |

Accounts exist only through invites: a magic link for an unknown address returns a pending-signup token, which only `POST /api/invites/{inviteId}/redeem` accepts. Signing in never grants keys. `POST /api/dev/session` exists only in binaries built with `-tags DEV`.

## Commands

```sh
make test      # gofmt, vet (with and without -tags DEV), tests; database tests skip
make test-db   # the same tests against the local PostgreSQL (TEST_DATABASE_URL)
make run       # serve on 127.0.0.1:8080 (LISTEN_ADDR to change; DATABASE_URL required)
make vectors   # regenerate testdata/vectors.json after a format change
make release   # build; refuses a dirty tree
```

`make test-db` defaults to `postgres://postgres@127.0.0.1:54329/duongondro_test?sslmode=disable`; set `TEST_DATABASE_URL` to use another server. Each test creates and drops its own schema, so packages run in parallel.

The binary applies migrations at startup and re-applies purges recorded in `purge_log` (after restoring a backup). Environment: `DATABASE_URL` (required), `LISTEN_ADDR`, `MAGIC_LINK_BASE` (default `https://duongondro.app/m#`).

`GET /api/version` reports the commit the binary was built from (with `-dirty` for development builds), which the apps show in Settings.

## Design

The product and architecture are documented in the design repository (private for now). The crypto and streak specs here are the normative versions.

## Licence

GNU Affero General Public License v3.0. If you run a modified version of this server for others, you must offer them its source.
