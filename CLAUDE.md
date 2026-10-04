# duongondro-api

Go backend for Duongöndro. The design lives in `Duongondro/duongondro-design` (read its `README.md` and `CLAUDE.md` first); this repository's `docs/crypto.md` and `docs/streaks.md` are the normative specs for the byte formats and the streak rules.

- **The server never sees plaintext counts, rounds or keys.** It stores sealed blobs and verifies only sizes, P-256 points (`e2ee.ParsePublicKey`) and Ed25519 signatures over the exact bytes received.
- **Specs, vectors and cases change together.** A format change updates `docs/crypto.md`, then `make vectors`, and the diff of `testdata/vectors.json` is reviewed. `testdata/streak-cases.json` expected values are worked out by hand from `docs/streaks.md`, never generated from the implementation.
- **Release builds refuse a dirty tree** (`make release`); development builds may be dirty and report `<hash>-dirty` from `GET /api/version`.
- **Logging:** never log tokens, query strings, sealed blobs, public keys or usernames; ERROR only for 5xx and crashes (CodeShare's rule).
- **Toolchain:** Go 1.24 for now. In sessions where the Go module proxy is unreachable, a local `go.work` (git-ignored) replaces `golang.org/x/crypto` and `golang.org/x/sys` with their GitHub mirrors and sets `GOPROXY=direct GOSUMDB=off`; `go.sum` keeps the canonical hashes, which CI verifies.
- Commits end with the attribution trailers the session asks for.
