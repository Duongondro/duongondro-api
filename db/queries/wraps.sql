-- name: PutWrap :exec
INSERT INTO key_wraps (device_id, kind, key_version, ephemeral_key, box, auth_type, authenticator)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (device_id, kind, key_version) DO UPDATE SET
    ephemeral_key = EXCLUDED.ephemeral_key, box = EXCLUDED.box,
    auth_type = EXCLUDED.auth_type, authenticator = EXCLUDED.authenticator, created_at = now();

-- name: ListWraps :many
SELECT * FROM key_wraps WHERE device_id = $1 ORDER BY kind, key_version;

-- name: PracticeKeyHolders :many
-- Devices holding a wrap of the given practice-key version: a rotation must wrap the
-- new key to exactly these.
SELECT devices.id, devices.public_key_encrypted FROM devices
JOIN key_wraps ON key_wraps.device_id = devices.id
WHERE devices.user_id = sqlc.arg(user_id) AND key_wraps.kind = 1 AND key_wraps.key_version = sqlc.arg(key_version)
ORDER BY devices.id;

-- name: LockUser :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: SetKeyVersion :execrows
UPDATE users SET key_version = sqlc.arg(new_version)
WHERE id = sqlc.arg(id) AND key_version = sqlc.arg(new_version)::integer - 1;

-- name: DeviceHoldsPracticeKey :one
-- Whether the account's device holds a wrap of the given practice-key version:
-- replacing the user key U is for a phone that holds the keys.
SELECT EXISTS (SELECT 1 FROM key_wraps JOIN devices ON devices.id = key_wraps.device_id
    WHERE key_wraps.device_id = sqlc.arg(device_id) AND devices.user_id = sqlc.arg(user_id)
      AND key_wraps.kind = 1 AND key_wraps.key_version = sqlc.arg(key_version));
