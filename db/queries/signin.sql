-- name: CreateUserWithID :one
INSERT INTO users (id) VALUES ($1) RETURNING *;

-- name: InviterOf :one
SELECT inviter_id FROM invites WHERE id = $1;

-- name: CreateCredential :exec
INSERT INTO credentials (id, user_id, data) VALUES ($1, $2, $3);

-- name: ListCredentials :many
SELECT * FROM credentials WHERE user_id = $1 ORDER BY created_at;

-- name: UpdateCredential :exec
UPDATE credentials SET data = $2, last_used_at = now() WHERE id = $1;

-- name: PurgeExpiredWebauthnSessions :execrows
DELETE FROM webauthn_sessions WHERE created_at <= now() - interval '5 minutes';

-- name: CreateWebauthnSession :one
INSERT INTO webauthn_sessions (data, user_id, invite_id, admission_id) VALUES ($1, $2, $3, $4) RETURNING id;

-- name: ConsumeWebauthnSession :one
DELETE FROM webauthn_sessions WHERE id = $1 AND created_at > now() - interval '5 minutes'
RETURNING *;

-- name: GetIdentity :one
SELECT * FROM auth_identities WHERE provider = $1 AND subject = $2;

-- name: CreateIdentity :exec
INSERT INTO auth_identities (provider, subject, user_id, email, refresh_token) VALUES ($1, $2, $3, $4, $5);

-- name: UpdateIdentity :exec
UPDATE auth_identities SET email = COALESCE(sqlc.narg(email), email),
    refresh_token = COALESCE(sqlc.narg(refresh_token), refresh_token)
WHERE provider = sqlc.arg(provider) AND subject = sqlc.arg(subject);

-- name: ListIdentities :many
SELECT * FROM auth_identities WHERE user_id = $1 ORDER BY created_at;

-- name: PurgeExpiredMagicLinks :execrows
DELETE FROM magic_links WHERE created_at <= now() - interval '15 minutes';

-- name: CountRecentMagicLinks :one
SELECT count(*) FROM magic_links WHERE lower(email) = lower($1) AND created_at > now() - interval '15 minutes';

-- name: CreateMagicLink :exec
INSERT INTO magic_links (token_hash, email, invite_id, admission_id, code_hash) VALUES ($1, $2, $3, $4, $5);

-- name: KillMagicLinkCodes :exec
-- A newer mail to the address makes the older codes unusable; their links still work.
UPDATE magic_links SET code_dead_at = now() WHERE lower(email) = lower($1) AND code_dead_at IS NULL;

-- name: ConsumeMagicLink :one
DELETE FROM magic_links
WHERE token_hash = $1 AND created_at > now() - interval '15 minutes'
RETURNING *;

-- name: LockLiveMagicLinkForEmail :one
-- The one live code to an address (a newer mail kills the older), for a typed code.
SELECT * FROM magic_links
WHERE lower(email) = lower($1) AND code_dead_at IS NULL AND code_hash IS NOT NULL
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
DELETE FROM magic_links WHERE lower(email) IN (
    SELECT lower(auth_identities.email) FROM auth_identities
    WHERE auth_identities.user_id = $1 AND auth_identities.email IS NOT NULL);

-- name: ExportCredentials :many
SELECT id, created_at, last_used_at FROM credentials WHERE user_id = $1 ORDER BY created_at;

-- name: ExportIdentities :many
SELECT provider, subject, email, created_at FROM auth_identities WHERE user_id = $1 ORDER BY created_at;

-- name: ExportMagicLinks :many
SELECT magic_links.email, magic_links.created_at FROM magic_links
WHERE lower(magic_links.email) IN (
    SELECT lower(auth_identities.email) FROM auth_identities
    WHERE auth_identities.user_id = $1 AND auth_identities.email IS NOT NULL);

-- name: DeleteWebauthnSessionsForUser :exec
DELETE FROM webauthn_sessions WHERE user_id = $1;

-- name: CreateNonce :exec
INSERT INTO auth_nonces (nonce_hash) VALUES ($1);

-- name: ConsumeNonce :execrows
DELETE FROM auth_nonces WHERE nonce_hash = $1 AND created_at > now() - interval '10 minutes';

-- name: PurgeExpiredNonces :exec
DELETE FROM auth_nonces WHERE created_at <= now() - interval '10 minutes';

-- name: LockEmail :exec
-- Serialises magic-link requests for one address, so the per-address limit holds.
SELECT pg_advisory_xact_lock(hashtextextended(lower(sqlc.arg(email)::text), 0));
