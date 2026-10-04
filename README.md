# duongondro-api

The Go backend for [Duongöndro](https://duongondro.app): track your meditation practice together with your friends, end-to-end encrypted and fully open source.

The server stores sealed blobs and signed public streaks. It never receives a practice count, a round number or a key: see [docs/crypto.md](docs/crypto.md).

## What is here

| Path | Contents |
| --- | --- |
| `docs/crypto.md` | Byte formats for sealed sessions, wraps, signed statements, invites, recovery |
| `docs/streaks.md` | The streak rules, including the jet-lag deadline |
| `testdata/vectors.json` | Crypto test vectors for the iOS and Android clients |
| `testdata/streak-cases.json` | Streak conformance cases every implementation must pass |
| `internal/e2ee` | Reference implementation of the crypto formats |
| `internal/streak` | Reference implementation of the streak rules |
| `api/openapi.yaml` | The API contract; the Android client is generated from it too |
| `db/migrations`, `db/queries` | goose migrations and sqlc queries (PostgreSQL 18) |
| `internal/server` | Echo strict server: authentication and DTO mapping |
| `internal/service` | The rules: what is checked before a key, wrap, signed statement or sealed log is stored |
| `internal/repository` | Transactions: practice-key rotation, the sync read |
| `cmd/duongondro-api` | The server binary (`serve`, `migrate`) |

## Commands

```sh
make db-setup  # create and migrate the local databases (Postgres 18)
make test      # gofmt, vet, every test (against duongondro_test)
make serve     # DEV build on 127.0.0.1:8080, with POST /api/dev/session for simulators
make gen       # regenerate the server from api/openapi.yaml and queries from db/
make vectors   # regenerate testdata/vectors.json after a format change
make release   # build; refuses a dirty tree and any trace of the DEV sign-in
make deploy    # build for FreeBSD and deploy to the shared server (deploy/deploy.yml)
```

Production is `duongondro` on the shared FreeBSD server set up by [shared-infrastructure](https://github.com/moroz/shared-infrastructure): service, database, env file and Caddy for `api.duongondro.app` and the apex's `/.well-known/` files. The service runs `./server migrate` before it starts; the server reads the env vars listed at the top of `cmd/duongondro-api/main.go`.

What exists so far: sessions, the Ed25519 identity key, devices with their key tier, the signed device list, wraps of the practice key and identity seed (signatures verified against an AAD the server rebuilds), practice-key rotation, sealed practice logs with last-write-wins and the `<generation>:<xid8>` sync cursor, recovery boxes; invitations (signed, reusable, rate-limited, auth stored hashed), friendships, blocks, reports, signed public streaks visible to friends only; the GDPR export and purge; and sign-in with passkeys, Sign in with Apple, Google and magic links, all creating accounts only with an invitation (Apple authorisations are revoked on deletion); and push through APNs and FCM: "done today" to friends who opted in, one poke per friend per day, and streak-at-risk two hours before a public streak's signed deadline, all as loc-keys the phones render in their own language. Magic links are mailed through SES in an EU region.

## Design

The product and architecture are documented in the design repository (private for now). The crypto and streak specs here are the normative versions.

## Licence

GNU Affero General Public License v3.0. If you run a modified version of this server for others, you must offer them its source.
