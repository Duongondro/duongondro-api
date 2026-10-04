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
