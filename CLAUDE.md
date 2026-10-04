# duongondro-api

Go backend for Duongöndro. The design lives in `Duongondro/duongondro-design` (read its `README.md` and `CLAUDE.md` first); this repository's `docs/crypto.md` and `docs/streaks.md` are the normative specs for the byte formats and the streak rules.

- **The server never sees plaintext counts, rounds or keys.** It stores sealed blobs and verifies only sizes, P-256 points (`e2ee.ParsePublicKey`) and Ed25519 signatures over the exact bytes received.
- **Specs, vectors and cases change together.** A format change updates `docs/crypto.md`, then `make vectors`, and the diff of `testdata/vectors.json` is reviewed. `testdata/streak-cases.json` expected values are worked out by hand from `docs/streaks.md`, never generated from the implementation.
- **The contract is `api/openapi.yaml`.** Handlers follow it by hand (no codegen for now, see `docs/stack.md`); `TestContractMatchesRoutes` fails when a route and the file disagree. Every API route lives under `/api/`, since the website is mounted at `/`.
- **Every table with a column referencing users must be exported and purged** (`internal/store/gdpr.go`). The GDPR tests derive those tables from `information_schema` and fail otherwise; every uuid column is either a foreign key to users or listed in `nonUserUUIDs`. Shipped migrations are never edited.
- **Integration tests** run with `make test-db` against local PostgreSQL, each in its own schema; `make test` skips them. Run both before pushing.
- **Release builds refuse a dirty tree** (`make release`); development builds may be dirty and report `<hash>-dirty` from `GET /api/version`.
- **Logging:** never log tokens, email addresses, query strings, sealed blobs, public keys, display names or usernames; identify people by user id. ERROR only for 5xx and crashes (CodeShare's rule).
- **No GitHub CI.** Build and test locally (`make test`) on the Mac.
- **Toolchain:** Go 1.24 for now, so no Echo v5 or sqlc yet (`docs/stack.md`). In sessions where the Go module proxy is unreachable, a local `go.work` (git-ignored) replaces the `golang.org/x/*` modules with their GitHub mirrors and Go runs with `GOPROXY=direct GOSUMDB=off`; `go.mod` keeps canonical paths and no replace directives, and `go.sum` keeps only canonical hashes.
- Commits end with the attribution trailers the session asks for.
