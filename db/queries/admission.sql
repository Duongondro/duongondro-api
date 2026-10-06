-- name: CreateAdmissionCode :exec
INSERT INTO admission_codes (code_hash, expires_at) VALUES ($1, $2);

-- name: GetLiveAdmissionCode :one
SELECT * FROM admission_codes WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: LockAdmissionCode :one
SELECT * FROM admission_codes WHERE id = $1 FOR UPDATE;

-- name: UseAdmissionCode :exec
UPDATE admission_codes SET used_by = sqlc.arg(used_by), used_at = now() WHERE id = sqlc.arg(id);

-- name: ExportAdmissionCodes :many
SELECT created_at, expires_at, used_at FROM admission_codes WHERE used_by = $1 ORDER BY created_at;
