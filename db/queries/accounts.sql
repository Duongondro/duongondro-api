-- name: CreateUser :one
INSERT INTO users DEFAULT VALUES RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: SetIdentityKey :execrows
-- Set once: a second, different key is refused (the service reports a conflict).
UPDATE users SET identity_public_key_encrypted = sqlc.arg(identity_public_key_encrypted)
WHERE id = sqlc.arg(id) AND identity_public_key_encrypted IS NULL;

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
-- The other phones stop receiving this account's pushes as well: every push token
-- of the user's devices but the one this session is bound to goes, in the same
-- statement (one snapshot). A phone signed out this way may never call again to
-- drop its own (the lost-phone case). An unbound session keeps no token: its app
-- sends it again within a day. A PUT of a token racing this statement (passed
-- authentication just before it commits) can keep that phone's token; accepted,
-- as the phone's next request finds its session gone and drops it itself.
WITH dropped AS (
    DELETE FROM push_tokens
    WHERE push_tokens.device_id IN (SELECT d.id FROM devices d WHERE d.user_id = $1)
      AND push_tokens.device_id IS DISTINCT FROM (SELECT s.device_id FROM sessions s WHERE s.token_hash = $2)
)
DELETE FROM sessions WHERE sessions.user_id = $1 AND sessions.token_hash <> $2;

-- name: KeyVersionForShare :one
-- Taken in the transaction that stores a log: a rotation, which locks the row FOR
-- UPDATE, waits for it, so no log lands under a version rotated away meanwhile.
SELECT key_version FROM users WHERE id = $1 FOR SHARE;

-- name: RecordPurge :exec
INSERT INTO purge_log (user_hash) VALUES ($1) ON CONFLICT DO NOTHING;

-- name: ReapplyPurges :execrows
-- After restoring a backup: delete again every account purged since.
DELETE FROM users WHERE sha256(uuid_send(id)) IN (SELECT user_hash FROM purge_log);
