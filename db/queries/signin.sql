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
INSERT INTO webauthn_sessions (data, user_id, invite_id) VALUES ($1, $2, $3) RETURNING id;

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
INSERT INTO magic_links (token_hash, email, invite_id) VALUES ($1, $2, $3);

-- name: ConsumeMagicLink :one
DELETE FROM magic_links WHERE token_hash = $1 AND created_at > now() - interval '15 minutes'
RETURNING *;

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
