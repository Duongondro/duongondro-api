-- name: GetUserKey :one
SELECT * FROM user_keys WHERE user_id = $1;

-- name: DeleteUserKey :exec
-- Replacing U: its wraps and passkey boxes cascade.
DELETE FROM user_keys WHERE user_id = $1;

-- name: DeleteUserKeyDeviceWraps :exec
-- Replacing U also drops the copies of the old one on the account's phones.
DELETE FROM key_wraps WHERE kind = 4 AND device_id IN (SELECT id FROM devices WHERE user_id = $1);

-- name: CreateUserKey :exec
INSERT INTO user_keys (user_id, id, version, payload_encrypted, signature) VALUES ($1, $2, $3, $4, $5);

-- name: PutUserKeyWrap :exec
INSERT INTO user_key_wraps (user_key_id, kind, key_version, ephemeral_key, box, signature)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_key_id, kind, key_version) DO UPDATE SET
    ephemeral_key = EXCLUDED.ephemeral_key, box = EXCLUDED.box, signature = EXCLUDED.signature, created_at = now();

-- name: ListUserKeyWraps :many
SELECT * FROM user_key_wraps WHERE user_key_id = $1 ORDER BY kind, key_version;

-- name: UserKeyHoldsPracticeKey :one
-- Whether U holds the given practice-key version: a rotation must then wrap to it.
SELECT EXISTS (SELECT 1 FROM user_key_wraps WHERE user_key_id = $1 AND kind = 1 AND key_version = $2);

-- name: PutPasskeyBox :exec
INSERT INTO passkey_boxes (credential_id, user_key_id, box, signature) VALUES ($1, $2, $3, $4)
ON CONFLICT (credential_id) DO UPDATE SET
    user_key_id = EXCLUDED.user_key_id, box = EXCLUDED.box, signature = EXCLUDED.signature, updated_at = now();

-- name: GetPasskeyBox :one
SELECT passkey_boxes.* FROM passkey_boxes JOIN credentials ON credentials.id = passkey_boxes.credential_id
WHERE passkey_boxes.credential_id = $1 AND credentials.user_id = $2;

-- name: DeletePasskeyBox :execrows
DELETE FROM passkey_boxes USING credentials
WHERE passkey_boxes.credential_id = $1 AND credentials.id = passkey_boxes.credential_id AND credentials.user_id = $2;

-- name: UnlockingCredentials :many
-- The account's passkeys with a box, all of them for the current U.
SELECT passkey_boxes.credential_id FROM passkey_boxes JOIN credentials ON credentials.id = passkey_boxes.credential_id
WHERE credentials.user_id = $1;

-- name: CredentialOwned :one
SELECT EXISTS (SELECT 1 FROM credentials WHERE id = $1 AND user_id = $2);

-- name: ExportPasskeyBoxes :many
SELECT passkey_boxes.* FROM passkey_boxes JOIN credentials ON credentials.id = passkey_boxes.credential_id
WHERE credentials.user_id = $1 ORDER BY passkey_boxes.credential_id;
