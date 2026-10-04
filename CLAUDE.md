# duongondro-api

Go backend for Duongöndro. The design lives in `Duongondro/duongondro-design` (read its `README.md` and `CLAUDE.md` first); this repository's `docs/crypto.md` and `docs/streaks.md` are the normative specs for the byte formats and the streak rules.

- **The server never sees plaintext counts, rounds or keys.** It stores sealed blobs and verifies only sizes, P-256 points (`e2ee.ParsePublicKey`) and Ed25519 signatures over the exact bytes received.
- **Specs, vectors and cases change together.** A format change updates `docs/crypto.md`, then `make vectors`, and the diff of `testdata/vectors.json` is reviewed. `testdata/streak-cases.json` expected values are worked out by hand from `docs/streaks.md`, never generated from the implementation.
- **Release builds refuse a dirty tree** (`make release`); development builds may be dirty and report `<hash>-dirty` from `GET /api/version`.
- **Logging:** never log tokens, query strings, sealed blobs, public keys or usernames; ERROR only for 5xx and crashes (CodeShare's rule).
- **No GitHub CI.** Build and test locally (`make test`) on the Mac.
- **Toolchain:** Go 1.27 (the stdlib `uuid` package), Echo v5 with an oapi-codegen strict server, pgx, sqlc, goose and PostgreSQL 18, CodeShare's stack. Tests need the local Postgres: `make db-setup` once, then `make test`.
- **Contract first:** edit `api/openapi.yaml`, then `make gen`; never edit `internal/api/api.gen.go` or `internal/db/*.go`. Sign-in routes are in the spec too (the Android client is generated from it; WebAuthn responses travel as JSON objects the service parses); only the DEV-only `POST /api/dev/session` stays outside it.
- **Layering:** `internal/server` authenticates and maps DTOs and errors only; `internal/service` holds the rules (what is checked before a key, wrap, statement or sealed log is stored); `internal/repository` holds transactions; single-table work calls sqlc directly. Service errors: `invalid(...)` → 400, `conflict(...)` → 409, `ErrNotFound` → 404 (another user's rows look missing), `OldKeyError` → 422; only `auth.ErrInvalidToken` becomes a 401.
- **Migrations:** `make db-new name=<snake_case>`, never a hand-typed version (`db/migrations` tests reject one); never edit or roll back a deployed migration, fix forward.
- **The DEV sign-in** exists only with `-tags DEV` (`make serve`); `make release` refuses a binary that contains it, as CodeShare's does. DEV builds also print magic links to stderr; release builds never log a link or token.
- **Sign-in rules:** an account is created only with a live invitation and its auth (`Social.CheckInvite`); signing in never grants keys; linking a method is explicit, from a signed-in session, never by a matching e-mail. Delete-account revokes Sign in with Apple first.
- Commits end with the attribution trailers the session asks for.
