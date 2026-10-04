-- name: SyncState :one
SELECT database_generation.id AS generation, pg_snapshot_xmax(pg_current_snapshot())::xid8 AS xmax
FROM database_generation;

-- name: SnapshotXmin :one
SELECT pg_snapshot_xmin(pg_current_snapshot())::xid8 AS xmin;

-- name: LogsChangedSince :many
SELECT * FROM practice_logs
WHERE user_id = sqlc.arg(user_id) AND xid >= sqlc.arg(since)::xid8
ORDER BY xid, id;

-- name: UpsertLog :one
-- Last write wins on the client's clock. A row of another user is never touched:
-- the WHERE fails, nothing returns, and the service answers 404.
INSERT INTO practice_logs (id, user_id, sealed, key_version, client_updated_at, deleted_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (id) DO UPDATE SET
    sealed = EXCLUDED.sealed, key_version = EXCLUDED.key_version,
    client_updated_at = EXCLUDED.client_updated_at, deleted_at = EXCLUDED.deleted_at,
    xid = pg_current_xact_id(), updated_at = now()
WHERE practice_logs.user_id = EXCLUDED.user_id
  AND practice_logs.client_updated_at < EXCLUDED.client_updated_at
RETURNING *;

-- name: GetLog :one
SELECT * FROM practice_logs WHERE id = $1;
