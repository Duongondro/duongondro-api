# Stack: where this server deviates from CodeShare

The design ([09 Backend and sync](https://github.com/Duongondro/duongondro-design/blob/main/docs/09-backend-sync.md)) calls for CodeShare's stack: Echo v5 strict server generated from the OpenAPI file, pgx, sqlc, goose, PostgreSQL 18. The first version was built in a session with Go 1.24 only and no Go module proxy, so it uses less:

| CodeShare | Here, for now | Why |
| --- | --- | --- |
| Echo v5 + oapi-codegen strict server | `net/http` `ServeMux` method patterns; handlers follow `api/openapi.yaml` by hand | Echo v4.16+ and v5 need Go 1.25 |
| sqlc | Hand-written SQL in `internal/store` | sqlc is a separate binary that could not be installed |
| goose | `internal/db`: embedded `migrations/*.sql`, applied in name order, each in its own transaction under an advisory lock, recorded in `schema_migrations`; shipped files are never edited | One less dependency; the behaviour is the part of goose CodeShare used |
| PostgreSQL 18 `uuidv7()` | UUIDv7 made in Go (`internal/ids`); `gen_random_uuid()` for the database generation | The build session has PostgreSQL 16 |
| go-webauthn passkeys, Sign in with Apple, Google | Magic links only | See TODO below |

Kept from CodeShare: pgx/v5, bearer tokens stored as SHA-256, the `<generation>:<xid8>` sync cursor in a REPEATABLE READ read-only transaction, last write wins on the client clock with the 24-hour future limit, 422 `currentKeyVersion`, CHECK constraints for every size, the 64 KiB body cap, the dev session compiled in only with `-tags DEV`, in-memory token-bucket rate limits with `X-Forwarded-For` trusted only from loopback, integration tests in a private schema per test, skipped without `TEST_DATABASE_URL`.

**Revisit on the Mac** with a current Go toolchain: move to Echo v5 strict server and sqlc (the repository layer's queries port one to one), goose if the migration runner grows, PostgreSQL 18 and `uuidv7()`.

## TODO

- **Passkeys** (go-webauthn, relying party `duongondro.app`), **Sign in with Apple** and **Google**: each signs in through `auth_identities` and, for an unknown subject, returns the same pending-signup token as a magic link, so an account still needs an invite. An Apple or Google identity whose email matches an account is linked only from a signed-in session.
- **Sign in with Apple revocation** on purge: `SignInWithAppleRevoker` is a no-op until Apple sign-in exists.
- **Email delivery** (SES, EU region): `EmailSender` only logs that a link was sent.
- **APNs and FCM delivery**: `push.Sender` only logs; the payload builders are final.
- **Avatar blobs**: `users.avatar_ref` is a reference the phone sets; the upload route is not built.
- **Streak-at-risk pushes** from `streak_statements.deadline`: needs a scheduler.
