# duongondro-api

The Go backend for [Duongöndro](https://duongondro.app): track your meditation practice together with your friends, end-to-end encrypted and fully open source.

The server stores sealed blobs and signed public streaks. It never receives a practice count, a round number or a key: see [docs/crypto.md](docs/crypto.md).

## What is here

| Path | Contents |
| --- | --- |
| `docs/crypto.md` | Byte formats for sealed sessions, wraps, signed statements, invites, recovery |
| `docs/streaks.md` | The streak rules, including the jet-lag deadline |
| `docs/at-rest.md` | Encryption at rest: the sealed columns, blind indexes, keys, migration and rotation |
| `testdata/vectors.json` | Crypto test vectors for the iOS and Android clients |
| `testdata/streak-cases.json` | Streak conformance cases every implementation must pass |
| `internal/e2ee` | Reference implementation of the crypto formats |
| `internal/streak` | Reference implementation of the streak rules |
| `internal/atrest` | Encryption at rest of the personal columns (XChaCha20-Poly1305, HMAC blind indexes) |
| `api/openapi.yaml` | The API contract; the Android client is generated from it too |
| `db/migrations`, `db/queries` | goose migrations and sqlc queries (PostgreSQL 18) |
| `internal/server` | Echo strict server: authentication and DTO mapping |
| `internal/service` | The rules: what is checked before a key, wrap, signed statement or sealed log is stored |
| `internal/repository` | Transactions: practice-key rotation, the sync read |
| `cmd/duongondro-api` | The server binary (`serve`, `migrate`, `reapply-purges`, `admit`) |

## Commands

```sh
make db-setup  # create and migrate the local databases (Postgres 18), with the DEV key
make test      # gofmt, vet, every test (against duongondro_test, or TEST_DATABASE_URL)
make serve     # DEV build on 127.0.0.1:8080, with POST /api/dev/session for simulators
make gen       # regenerate the server from api/openapi.yaml and queries from db/
make vectors   # regenerate testdata/vectors.json after a format change
make release   # build; refuses a dirty tree and any trace of the DEV sign-in
make deploy    # build for FreeBSD and deploy to the shared server (deploy/deploy.yml)
```

Another port or database for the DEV server, when 8080 or the shared local database is taken (the DEV build seals with its built-in development key unless `SECRET_KEY_BASE` is set):

```sh
DATABASE_URL=postgres://$USER@localhost/duongondro_mine LISTEN_ADDR=127.0.0.1:8081 \
  RP_ID=localhost RP_ORIGINS=http://localhost:8081 go run -tags DEV ./cmd/duongondro-api serve
```

## Encryption at rest

Every personal column the server must read (display names, usernames, genders, e-mail addresses, sign-in subjects, Apple refresh tokens, passkeys, push tokens, report texts, public keys and signed statements) is sealed with XChaCha20-Poly1305 under a key derived from `SECRET_KEY_BASE`, bound to its table, column and row; lookups go through HMAC blind indexes. A dump or backup of the database reveals none of them. Details, the column list and what stays plain: [docs/at-rest.md](docs/at-rest.md).

**Release builds refuse to start without `SECRET_KEY_BASE`**, and so does `server migrate`, which the service runs first. Before the first deploy that includes it, the owner:

1. Generates the key once and keeps it with the other secrets; losing it loses every sealed column (a backup does not help, since it holds only ciphertext):

   ```sh
   openssl rand -base64 64 | tr -d '\n'
   ```

2. Adds it to the vault in shared-infrastructure, beside `SMTP_LOGIN` and `SMTP_TOKEN` (base64 has no `"`, `$`, `\` or backtick, so it is safe in the env file), and writes the env file on the server:

   ```sh
   mise exec -- ansible-vault edit group_vars/all/vault.yml   # project_secrets.duongondro.SECRET_KEY_BASE
   mise run provision -- --tags projects -e only_projects=duongondro
   ```

   Nothing else changes in `group_vars/all/vars.yml`; its duongondro comment may mention the new secret. A restored backup needs the same key, so the vault copy is the one to keep.
3. Runs the read-only check in [docs/at-rest.md](docs/at-rest.md#before-deploying) against production: no rows means no two e-mail sign-ins become one address. (The migration checks again and stops, changing nothing, if any do.)
4. Takes a backup right before deploying, which is also the only way back (step 7):

   ```sh
   sudo -u duongondro sh -c 'set -a; . /path/to/duongondro.env; exec pg_dump -Fc "$DATABASE_URL"' > duongondro-before-at-rest.dump
   ```

   It holds the plain values: keep it private and delete it once the deploy has settled.
5. Optionally rehearses the migration on a local restore of that backup, with a release build and the real key:

   ```sh
   createdb duongondro_restore_test && pg_restore --no-owner -d duongondro_restore_test duongondro-before-at-rest.dump
   DATABASE_URL=postgres:///duongondro_restore_test SECRET_KEY_BASE='…' go run ./cmd/duongondro-api migrate
   dropdb duongondro_restore_test
   ```

6. Deploys (`make deploy`). The restart runs `./server migrate`: one migration adds the empty sealed columns; the next, in a single transaction, seals every existing row and drops the plain columns (seconds at today's size); the last rewrites those tables (`VACUUM FULL`; a table a running backup holds is skipped with a warning in the log, to rewrite by hand later). Then the server starts. If the key is missing, migrate exits before touching the database and the service stays down until it is added and the service restarted. If sealing fails, its transaction rolls back and only the empty columns remain, which the old release ignores.
7. Checks that `GET /api/version` shows the new revision and the apps work as before. **Once the sealing migration has committed, the old release cannot read the database: never restart it (nor point `current` at an older release).** The only rollback is restoring the backup from step 4, losing what was written since. Backups taken before the deploy still hold the plain values until they expire (30 days); newer ones hold only ciphertext.

Rotating the key later: set the new key as `SECRET_KEY_BASE` and the old one as `SECRET_KEY_BASE_PREVIOUS`, restart (migrate reseals every row under the new key before the server starts), then remove `SECRET_KEY_BASE_PREVIOUS` and restart again.

## Admission codes

Until open sign-up (below) is switched on, sign-up is invitation-only, and invitations come from members, so the first members need another way in: single-use admission codes. `duongondro-api admit` prints fresh ones, 16 Crockford base32 characters in groups of four, and stores only their SHA-256, so the printout is the only copy:

```sh
DATABASE_URL=postgres://$USER@localhost/duongondro go run ./cmd/duongondro-api admit -n 5 -days 30
```

`-n` is how many (default 5), `-days` how long they last (default 30). A code works wherever an invitation does (passkey, Apple, Google and magic-link sign-up), typed in any case, with or without spaces or hyphens, O for 0 and I or L for 1. The account it makes is a root of the invite tree: no inviter, no friendship.

In production, run the deployed binary on the shared server as the `duongondro` service user, with the service's environment: the env file shared-infrastructure installs for the project (its path is set there, not here), which sets `DATABASE_URL`. Sourcing it keeps the database password off the command line:

```sh
sudo -u duongondro sh -c 'set -a; . /path/to/duongondro.env; exec /usr/local/lib/duongondro/current/server admit -n 5'
```

Hand each code to one person over a private channel; a spent or expired code is refused with the same 404 as an unknown invitation.

## Open sign-up

With `OPEN_SIGNUP=true` in the service's environment (default off; set in shared-infrastructure, so opening is a deploy, not a build), anyone can make an account (design: Social › Open sign-up, decision 20). A sign-up request then says it is one, `"signUp": true` with `"consent": true` (the onboarding's GDPR Art. 9 checkbox), on `POST /api/auth/passkeys/sign-up`, `POST /api/auth/providers/{provider}` or `POST /api/auth/magic-links`, and needs no invitation or admission code. The account is a root of the invite tree with no friends, as with an admission code. Invitations and codes still work beside it, with or without the flag: a friend's invitation still makes the two friends, and a request that carries one without the flag (Android 0.3) is a sign-up as before. With the switch off, a flagged sign-up without an invitation or code is answered 403; without the flag, as before.

Passkey, Apple and Google sign-ups without an invitation are limited to five accounts an hour per client address (429), counted when the account is made; a passkey ceremony is also refused at its start once the address is at the limit. The count lives only in the process's memory, keyed by an HMAC of the address under a per-process key, and is never logged or stored; a restart resets it. E-mail sign-ups are not counted: the magic link's own limits apply (three mails per address per 15 minutes, five wrong codes).

The public website for `duongondro.app` lives in `web/` (see its README) and is served by the same binary on the hosts in `WEB_HOSTS`.

Production is `duongondro` on the shared FreeBSD server set up by [shared-infrastructure](https://github.com/moroz/shared-infrastructure): service, database, env file and Caddy for `api.duongondro.app` and the apex's `/.well-known/` files. The service runs `./server migrate` before it starts; the server reads the env vars listed at the top of `cmd/duongondro-api/main.go`, `SECRET_KEY_BASE` among them (see Encryption at rest).

What exists so far: encryption at rest of every personal column (above); sessions, the Ed25519 identity key, devices with their key tier, the signed device list, wraps of the practice key and identity seed (signatures verified against an AAD the server rebuilds), practice-key rotation, sealed practice logs with last-write-wins and the `<generation>:<xid8>` sync cursor, recovery boxes; invitations (signed, reusable, rate-limited, auth stored hashed), friendships, blocks, reports, signed public streaks visible to friends only; a profile of display name, optional username (lowercase, unique, naming the passkeys, never shown to friends) and optional gender (shown to friends for grammatical forms), set by PATCH /api/me or already with a passkey sign-up; the GDPR export (which, in its friend list, includes friends' display names and genders, as the app shows them) and purge; and sign-in with passkeys, Sign in with Apple, Google and magic links, all creating accounts only with an invitation or a single-use admission code, or with open sign-up switched on (Apple authorisations are revoked on deletion); and push through APNs and FCM: "done today" to friends who opted in, one poke per friend per day, and streak-at-risk two hours before a public streak's signed deadline, all as loc-keys the phones render in their own language. Magic links are mailed over SMTP through Brevo's relay, with the token in the URL fragment and an 8-character code to type instead (five wrong guesses or a newer mail kill the code, never the link, so guessing locks nobody out). Codes are stored as an HMAC under a key each server process draws at start and keeps only in memory, so a database reader cannot brute-force their 40 bits; a restart or deploy therefore invalidates codes already mailed, while their links keep working.

## Design

The product and architecture are documented in the design repository (private for now). The crypto and streak specs here are the normative versions.

## Licence

GNU Affero General Public License v3.0. If you run a modified version of this server for others, you must offer them its source.
