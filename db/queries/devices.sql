-- name: CreateDevice :one
INSERT INTO devices (user_id, public_key, tier) VALUES ($1, $2, $3)
ON CONFLICT (user_id, public_key) DO NOTHING
RETURNING *;

-- name: GetDeviceByKey :one
SELECT * FROM devices WHERE user_id = $1 AND public_key = $2;

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
INSERT INTO device_lists (user_id, version, payload, signature) VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET
    version = EXCLUDED.version, payload = EXCLUDED.payload,
    signature = EXCLUDED.signature, updated_at = now()
WHERE device_lists.version < EXCLUDED.version;
