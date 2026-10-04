-- Everything the server holds about one user, for GET /api/me/export. A new table
-- needs a query here and a place in service.Export; internal/service's
-- TestExportCoversEveryTable fails until it has one.

-- name: ExportSessions :many
SELECT created_at FROM sessions WHERE user_id = $1 ORDER BY created_at;

-- name: ExportWraps :many
SELECT key_wraps.* FROM key_wraps JOIN devices ON devices.id = key_wraps.device_id
WHERE devices.user_id = $1 ORDER BY key_wraps.device_id, key_wraps.kind, key_wraps.key_version;

-- name: ExportLogs :many
SELECT * FROM practice_logs WHERE user_id = $1 ORDER BY id;

-- name: ExportInviteNode :one
SELECT node_id, parent_id, created_at FROM invite_tree WHERE user_id = $1;

-- name: ExportRedemptions :many
SELECT * FROM invite_redemptions WHERE invitee_id = $1 ORDER BY created_at;

-- name: ExportReports :many
SELECT id, reported_id, reason, created_at FROM reports WHERE reporter_id = $1 ORDER BY created_at;
