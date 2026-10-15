-- name: CreateUserWithID :one
INSERT INTO users (id) VALUES ($1) RETURNING *;

-- name: InviterOf :one
SELECT inviter_id FROM invites WHERE id = $1;

-- name: CreateCredential :exec
INSERT INTO credentials (id, user_id, data_encrypted) VALUES ($1, $2, $3);

-- name: ListCredentials :many
SELECT * FROM credentials WHERE user_id = $1 ORDER BY created_at;

-- name: UpdateCredential :exec
UPDATE credentials SET data_encrypted = $2, last_used_at = now() WHERE id = $1;

-- name: PurgeExpiredWebauthnSessions :execrows
DELETE FROM webauthn_sessions WHERE created_at <= now() - interval '5 minutes';

-- name: CreateWebauthnSession :exec
-- The id is drawn by the caller: the sealed profile is bound to it. data holds the
-- challenge, relying party and account id only (no personal data), so it stays plain.
INSERT INTO webauthn_sessions (id, data, user_id, invite_id, admission_id, username_encrypted, display_name_encrypted, gender_encrypted, sign_up)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ConsumeWebauthnSession :one
DELETE FROM webauthn_sessions WHERE id = $1 AND created_at > now() - interval '5 minutes'
RETURNING *;

-- name: GetIdentity :one
SELECT * FROM auth_identities WHERE provider = $1 AND subject_hash = $2;

-- name: CreateIdentity :exec
INSERT INTO auth_identities (provider, subject_encrypted, subject_hash, user_id, email_encrypted, email_hash, refresh_token_encrypted)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: UpdateIdentity :exec
-- The address and its hash change together, or not at all.
UPDATE auth_identities SET email_encrypted = COALESCE(sqlc.narg(email_encrypted), email_encrypted),
    email_hash = COALESCE(sqlc.narg(email_hash), email_hash),
    refresh_token_encrypted = COALESCE(sqlc.narg(refresh_token_encrypted), refresh_token_encrypted)
WHERE provider = sqlc.arg(provider) AND subject_hash = sqlc.arg(subject_hash);

-- name: ListIdentities :many
SELECT * FROM auth_identities WHERE user_id = $1 ORDER BY created_at;

-- name: PurgeExpiredMagicLinks :execrows
DELETE FROM magic_links WHERE created_at <= now() - interval '15 minutes';

-- name: CountRecentMagicLinks :one
SELECT count(*) FROM magic_links WHERE email_hash = $1 AND created_at > now() - interval '15 minutes';

-- name: CreateMagicLink :exec
INSERT INTO magic_links (token_hash, email_encrypted, email_hash, invite_id, admission_id, code_hash, sign_up) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: KillMagicLinkCodes :exec
-- A newer mail to the address makes the older codes unusable; their links still work.
UPDATE magic_links SET code_dead_at = now() WHERE email_hash = $1 AND code_dead_at IS NULL;

-- name: ConsumeMagicLink :one
DELETE FROM magic_links
WHERE token_hash = $1 AND created_at > now() - interval '15 minutes'
RETURNING *;

-- name: LockLiveMagicLinkForEmail :one
-- The one live code to an address (a newer mail kills the older), for a typed code.
SELECT * FROM magic_links
WHERE email_hash = $1 AND code_dead_at IS NULL AND code_hash IS NOT NULL
    AND created_at > now() - interval '15 minutes'
ORDER BY created_at DESC LIMIT 1
FOR UPDATE;

-- name: RecordWrongMagicLinkCode :exec
-- The fifth wrong code kills the code; the link still works.
UPDATE magic_links SET wrong_codes = wrong_codes + 1,
    code_dead_at = CASE WHEN wrong_codes + 1 >= sqlc.arg(max_wrong)::smallint THEN now() ELSE code_dead_at END
WHERE token_hash = sqlc.arg(token_hash);

-- name: DeleteMagicLink :exec
DELETE FROM magic_links WHERE token_hash = $1;

-- name: DeleteMagicLinksForUser :exec
-- A purge also drops unused links to the user's addresses.
DELETE FROM magic_links WHERE email_hash IN (
    SELECT auth_identities.email_hash FROM auth_identities
    WHERE auth_identities.user_id = $1 AND auth_identities.email_hash IS NOT NULL);

-- name: ExportCredentials :many
SELECT id, created_at, last_used_at FROM credentials WHERE user_id = $1 ORDER BY created_at;

-- name: ExportIdentities :many
SELECT provider, subject_hash, subject_encrypted, email_encrypted, created_at FROM auth_identities WHERE user_id = $1 ORDER BY created_at;

-- name: ExportMagicLinks :many
SELECT magic_links.token_hash, magic_links.email_encrypted, magic_links.created_at FROM magic_links
WHERE magic_links.email_hash IN (
    SELECT auth_identities.email_hash FROM auth_identities
    WHERE auth_identities.user_id = $1 AND auth_identities.email_hash IS NOT NULL);

-- name: DeleteWebauthnSessionsForUser :exec
DELETE FROM webauthn_sessions WHERE user_id = $1;

-- name: CreateNonce :exec
INSERT INTO auth_nonces (nonce_hash) VALUES ($1);

-- name: ConsumeNonce :execrows
DELETE FROM auth_nonces WHERE nonce_hash = $1 AND created_at > now() - interval '10 minutes';

-- name: PurgeExpiredNonces :exec
DELETE FROM auth_nonces WHERE created_at <= now() - interval '10 minutes';

-- name: LockEmail :exec
-- Serialises magic-link requests for one address, so the per-address limit holds:
-- the key is the first 8 bytes of the address's hash (atrest.LockKey).
SELECT pg_advisory_xact_lock(sqlc.arg(key)::bigint);
