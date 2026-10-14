# Encryption at rest

The server's own column encryption, for what it must be able to read: names, e-mail addresses, sign-in subjects, push tokens, public keys and signed statements. A database dump, a leaked backup, or another project's role on the shared host reading the database learns none of them. The running server holds the key, so a compromise of the process reads these columns, as it could read requests; that is the gap between this and the end-to-end sealing in [crypto.md](crypto.md). Decided as decision 17 ([design: Backend and sync › Encryption at rest](https://github.com/Duongondro/duongondro-design/blob/main/docs/09-backend-sync.md#encryption-at-rest)); `internal/atrest` is the implementation.

**The rule:** every column holding personal data is sealed. Plain are only random ids and the foreign keys between them, timestamps, fixed enum values, sizes and counters, hashes, signatures, and what is already end-to-end sealed. `TestEveryColumnIsClassified` (internal/service) fails the build when a text, bytea or json column is neither sealed, a blind index, nor listed as plain with its reason.

## Keys

`SECRET_KEY_BASE` is base64 of 64 random bytes (`openssl rand -base64 64 | tr -d '\n'`; at least 32 are required), set in the service's environment from the vault, never in the database or its backups. HKDF-SHA512 without salt derives, as homeosapiens-go does:

| Key | Size | HKDF info |
| --- | --- | --- |
| column key | 32 | `ColumnLevelEncryption` |
| blind-index key | 32 | `DatabaseHMAC` |
| key id | 4 | `ColumnLevelEncryptionKeyId` |

Release builds refuse to start (`serve`, `migrate`, `reseal`, `reapply-purges`) without `SECRET_KEY_BASE`; DEV builds fall back to a fixed development key. Vectors computed with OpenSSL are in `internal/atrest/atrest_test.go`.

## Sealed values

```
sealed = 0x01 ‖ keyId(4) ‖ nonce(24) ‖ XChaCha20-Poly1305(columnKey, nonce, PKCS7(plaintext, 32), aad)
aad    = "duongondro/at-rest/v1" ‖ lp(table) ‖ lp(column) ‖ lp(row) ‖ 0x01 ‖ keyId
lp(x)  = u16be(len(x)) ‖ x
row    = lp(part₁) ‖ lp(part₂) ‖ …     the row's primary key: uuid as 16 bytes, text as UTF-8, bytea as is
```

The nonce is random. PKCS#7 pads to 32-byte blocks (a full block when already aligned), so a stored length gives away a range, not the length of a name. The AAD binds a value to its table, its column (the database name, `display_name_encrypted`), its row and its key: copied to another row or column, it does not open. The key id says which `SECRET_KEY_BASE` sealed it. Sealed columns are `bytea` named `<name>_encrypted`; sqlc keeps those names (`DisplayNameEncrypted`), so ciphertext is never mistaken for plaintext, and `internal/atrest` opens rows into plain structs (`atrest.User`). go-sqlcrypter's `EncryptedBytes` was the plan, but its Scan sees a value without its row, so it cannot bind one; sealing here is explicit instead, in `internal/service` and `internal/repository`.

## Blind indexes

A value the server looks up gets `<name>_hash = HMAC-SHA256(blindIndexKey, normalised value)` beside it: equality only. E-mail addresses are normalised by trimming surrounding whitespace, Unicode NFC and lower-casing the whole address, with no provider rules (Gmail's dots and plus tags stay distinct); they are stored, mailed and hashed in that form. For the `email` provider the subject is the normalised address, so its `subject_hash` equals the address's `email_hash`. Every lookup, uniqueness check, rate limit and purge of an address goes through the hash; the per-address advisory lock takes the hash's first 8 bytes as its key. Logs show neither an address nor its hash.

## Columns

| Table | Sealed | Blind index | Row |
| --- | --- | --- | --- |
| `users` | `identity_public_key`, `display_name` (NULL when empty), `username`, `gender` | `username_hash` (unique) | `id` |
| `devices` | `public_key` | `public_key_hash` (unique with `user_id`) | `id` |
| `device_lists` | `payload` | | `user_id` |
| `invites` | `payload` | | `id` |
| `invite_redemptions` | `payload` | | `invite_id`, `invitee_id` |
| `reports` | `reason` | | `id` |
| `streaks` | `practice`, `payload` | `practice_hash` (primary key with `user_id`) | `user_id`, `practice_hash` |
| `credentials` | `data` (the passkey: public key, sign count) | | `id` |
| `webauthn_sessions` | `username`, `display_name`, `gender` | | `id` |
| `auth_identities` | `subject`, `email`, `refresh_token` | `subject_hash` (primary key with `provider`), `email_hash` | `provider`, `subject_hash` |
| `magic_links` | `email` | `email_hash` (limit, lock, lookup) | `token_hash` |
| `push_tokens` | `token` | `token_hash` (unique with `platform`) | `device_id` |

Rows whose ids the database used to draw (devices, reports, passkey ceremonies) now get them from the service, which needs the id to seal. Signed statements are verified on the bytes received, sealed, and open to exactly those bytes, so friends' phones verify them as before; the signatures stay plain. Plain on purpose, with the reasons in `plainColumns` (internal/service/atrest_test.go): hashes of tokens, codes and nonces; signatures; key wraps, recovery boxes and practice logs (end-to-end sealed); invite ids and macs; credential ids; enum values; and a passkey ceremony's state (challenge, relying party and account id, deleted within five minutes). Still plain beside them, and said so in the privacy policy: that an account exists, the links between accounts (friendships, invitations, blocks, pokes, reports), when each thing was written, sizes, a public streak's deadline and sequence number, and which kinds of sign-in, device and push service an account uses.

## Migrating

Three goose migrations, all run by `server migrate`, which the service runs before it starts:

1. `encrypt_columns` adds the `_encrypted` and `_hash` columns beside the plain ones, empty and nullable.
2. `encrypt_columns_backfill`, a Go migration (`db/migrations/*.go`, handed to goose with the keys by `migrations.Go`), seals every plain value and computes the hashes, normalising stored addresses, deletes passkey ceremonies in flight, and then, in the same transaction, runs `drop_plain_columns.sql`: the plain columns go, and primary keys, uniqueness and indexes move to the hashes. Sealing and dropping commit together or not at all; a failure leaves only step 1's empty columns. goose itself never runs that `.sql` file (`migrations.GooseFS` hides it); it stays in version order for sqlc. The migration uses plain SQL against that version's schema, never sqlc, so a fresh database runs it too.
3. `rewrite_encrypted_tables` runs `VACUUM FULL` on those tables, so the dropped values and old row versions leave the tables' files.

## Before deploying

The new primary key of `auth_identities` is `(provider, subject_hash)`, and an e-mail subject is now hashed in NFC. The old code stored addresses trimmed and lower-cased but not normalised, so two accounts may hold one address typed once composed and once decomposed. Step 2 checks this before it writes anything and, if so, fails naming the accounts. The same check, read-only, against production (or a restored backup) before deploying:

```sql
-- No rows: nothing collides.
SELECT lower(normalize(subject, NFC)) AS address, array_agg(user_id) AS accounts
FROM auth_identities WHERE provider = 'email'
GROUP BY 1 HAVING count(*) > 1;
```

Postgres's `lower` follows the database's locale rather than Go's case mapping, so treat a hit as certain and an empty result as very likely; the migration's own check is the exact one. A hit is resolved by hand: decide which account keeps the address and delete the other identity.

## Rotating the key

1. Set `SECRET_KEY_BASE` to a new key and `SECRET_KEY_BASE_PREVIOUS` to the old one, and restart: `server migrate` sees the previous key and reseals every value not under the current key, recomputing the row's blind indexes (the new key changes them too), one transaction per table. `duongondro-api reseal` does the same without migrating; running either again changes nothing.
2. Remove `SECRET_KEY_BASE_PREVIOUS` and restart. A value still under the old key would then fail to open, which is why the reseal runs before the server starts.

## Tests

- `internal/atrest`: key-derivation and HMAC vectors from OpenSSL, a pinned sealed value opened by hand from the layout above, AAD binding, rotation, padding, normalisation.
- `TestEveryColumnIsClassified`: every text, bytea and json column is sealed, a blind index, or plain with a reason.
- `TestDumpRevealsNoSealedPlaintext`: `pg_dump` of a database with a row in every table shows no sealed value, in plain or as bytea hex.
- `TestMigrationSealsExistingRows` (internal/migrate): rows written under the old schema open to their values after the migrations, and the blind indexes find them.
- `TestResealRotatesEveryValue`, `TestMigrateReseals`: a rotation leaves the export unchanged and the new key alone sufficient.
