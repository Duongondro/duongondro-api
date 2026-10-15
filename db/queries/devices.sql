-- name: CreateDevice :one
-- The id is drawn by the caller: the sealed key is bound to it.
INSERT INTO devices (id, user_id, public_key_encrypted, public_key_hash, tier) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, public_key_hash) DO NOTHING
RETURNING *;

-- name: GetDeviceByKey :one
SELECT * FROM devices WHERE user_id = $1 AND public_key_hash = $2;

-- name: GetDevice :one
SELECT * FROM devices WHERE id = $1;

-- name: ListDevices :many
SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at, id;

-- name: DeleteDevice :execrows
DELETE FROM devices WHERE id = $1 AND user_id = $2;

-- name: GetDeviceList :one
SELECT * FROM device_lists WHERE user_id = $1;

-- name: PutDeviceList :execrows
-- Only a higher version replaces the stored list.
INSERT INTO device_lists (user_id, version, payload_encrypted, signature) VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET
    version = EXCLUDED.version, payload_encrypted = EXCLUDED.payload_encrypted,
    signature = EXCLUDED.signature, updated_at = now()
WHERE device_lists.version < EXCLUDED.version;
