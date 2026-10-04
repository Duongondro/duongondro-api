-- name: CreateUser :one
INSERT INTO users DEFAULT VALUES RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: SetIdentityKey :execrows
-- Set once: a second, different key is refused (the service reports a conflict).
UPDATE users SET identity_public_key = sqlc.arg(identity_public_key)
WHERE id = sqlc.arg(id) AND identity_public_key IS NULL;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = $1;

-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2);

-- name: GetSessionUser :one
SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
WHERE sessions.token_hash = $1;

-- name: DeleteSession :execrows
DELETE FROM sessions WHERE token_hash = $1;

-- name: LockInvite :one
SELECT * FROM invites WHERE id = $1 FOR UPDATE;

-- name: GetSession :one
SELECT * FROM sessions WHERE token_hash = $1;

-- name: BindSessionDevice :exec
-- The device a session registered; the session ends when the device is removed.
UPDATE sessions SET device_id = $2 WHERE token_hash = $1 AND device_id IS NULL;

-- name: DeleteOtherSessions :execrows
DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2;

-- name: KeyVersionForShare :one
-- Taken in the transaction that stores a log: a rotation, which locks the row FOR
-- UPDATE, waits for it, so no log lands under a version rotated away meanwhile.
SELECT key_version FROM users WHERE id = $1 FOR SHARE;

-- name: RecordPurge :exec
INSERT INTO purge_log (user_hash) VALUES ($1) ON CONFLICT DO NOTHING;

-- name: ReapplyPurges :execrows
-- After restoring a backup: delete again every account purged since.
DELETE FROM users WHERE sha256(uuid_send(id)) IN (SELECT user_hash FROM purge_log);
