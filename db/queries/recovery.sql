-- name: PutRecoveryBox :exec
INSERT INTO recovery_boxes (user_id, kind, box, signature) VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, kind) DO UPDATE SET box = EXCLUDED.box, signature = EXCLUDED.signature, updated_at = now();

-- name: ListRecoveryBoxes :many
SELECT * FROM recovery_boxes WHERE user_id = $1 ORDER BY kind;
