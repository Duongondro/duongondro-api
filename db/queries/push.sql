-- name: ReleasePushToken :exec
-- A token reaches one device: drop it from any other before storing it.
DELETE FROM push_tokens WHERE platform = $1 AND token = $2 AND device_id <> $3;

-- name: PutPushToken :exec
INSERT INTO push_tokens (device_id, platform, token) VALUES ($1, $2, $3)
ON CONFLICT (device_id) DO UPDATE SET platform = EXCLUDED.platform, token = EXCLUDED.token, updated_at = now();

-- name: DeletePushToken :execrows
DELETE FROM push_tokens WHERE device_id = $1;

-- name: DropPushToken :exec
-- The provider reported the token unregistered.
DELETE FROM push_tokens WHERE platform = $1 AND token = $2;

-- name: PushTokensOf :many
SELECT push_tokens.* FROM push_tokens JOIN devices ON devices.id = push_tokens.device_id
WHERE devices.user_id = $1;

-- name: SetNotifyDone :execrows
UPDATE friendships SET notify_done = $3 WHERE user_id = $1 AND friend_id = $2;

-- name: DoneTodayRecipients :many
-- Friends who asked to hear when this user practises, and are not blocked either way
-- (a block removes the friendship, so this is the friendship alone).
SELECT user_id FROM friendships WHERE friend_id = $1 AND notify_done;

-- name: RecordNudge :execrows
INSERT INTO nudges (sender_id, recipient_id, day) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;

-- name: StreaksAtRisk :many
-- Public streaks whose deadline is under two hours away, not yet nudged for this
-- statement, and still alive.
SELECT * FROM streaks
WHERE deadline_at > now() AND deadline_at <= now() + interval '2 hours' AND at_risk_sent_seq < seq
ORDER BY deadline_at
LIMIT 500;

-- name: MarkAtRiskSent :exec
UPDATE streaks SET at_risk_sent_seq = $3 WHERE user_id = $1 AND practice = $2 AND seq = $3;

-- name: ExportPushTokens :many
SELECT push_tokens.device_id, push_tokens.platform, push_tokens.updated_at FROM push_tokens
JOIN devices ON devices.id = push_tokens.device_id WHERE devices.user_id = $1;

-- name: ExportNudges :many
SELECT * FROM nudges WHERE sender_id = $1 OR recipient_id = $1 ORDER BY created_at;
