-- name: SetDisplayName :exec
UPDATE users SET display_name = $2 WHERE id = $1;

-- name: CreateInviteNode :exec
-- Every account gets a node; parent_id is the inviter's node (NULL for the first
-- members and DEV accounts).
INSERT INTO invite_tree (user_id, parent_id)
VALUES (sqlc.arg(user_id), (SELECT node_id FROM invite_tree WHERE invite_tree.user_id = sqlc.narg(inviter_id)));

-- name: CreateInvite :exec
INSERT INTO invites (id, inviter_id, auth_hash, payload, signature, mac, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetLiveInvite :one
SELECT * FROM invites WHERE id = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: ListInvites :many
SELECT * FROM invites WHERE inviter_id = $1 ORDER BY created_at DESC;

-- name: RevokeInvite :execrows
UPDATE invites SET revoked_at = now() WHERE id = $1 AND inviter_id = $2 AND revoked_at IS NULL;

-- name: RecordRedemption :exec
INSERT INTO invite_redemptions (invite_id, invitee_id, payload, signature) VALUES ($1, $2, $3, $4)
ON CONFLICT (invite_id, invitee_id) DO NOTHING;

-- name: Befriend :exec
INSERT INTO friendships (user_id, friend_id) VALUES ($1, $2), ($2, $1)
ON CONFLICT DO NOTHING;

-- name: Unfriend :execrows
DELETE FROM friendships WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1);

-- name: ListFriends :many
SELECT users.id, users.display_name, users.identity_public_key, friendships.created_at
FROM friendships JOIN users ON users.id = friendships.friend_id
WHERE friendships.user_id = $1
ORDER BY friendships.created_at, users.id;

-- name: AreFriends :one
SELECT EXISTS (SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2);

-- name: IsBlockedEitherWay :one
SELECT EXISTS (
    SELECT 1 FROM blocks
    WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1));

-- name: Block :exec
INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: Unblock :execrows
DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2;

-- name: ListBlocks :many
SELECT * FROM blocks WHERE blocker_id = $1 ORDER BY created_at;

-- name: CreateReport :one
INSERT INTO reports (reporter_id, reported_id, reason) VALUES ($1, $2, $3) RETURNING id;

-- name: PutStreak :execrows
-- Only a higher seq replaces the stored statement.
INSERT INTO streaks (user_id, practice, seq, payload, signature, deadline_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id, practice) DO UPDATE SET
    seq = EXCLUDED.seq, payload = EXCLUDED.payload, signature = EXCLUDED.signature,
    deadline_at = EXCLUDED.deadline_at, updated_at = now()
WHERE streaks.seq < EXCLUDED.seq;

-- name: DeleteStreak :execrows
DELETE FROM streaks WHERE user_id = $1 AND practice = $2;

-- name: FriendsStreaks :many
SELECT streaks.* FROM streaks
JOIN friendships ON friendships.friend_id = streaks.user_id
WHERE friendships.user_id = $1
ORDER BY streaks.user_id, streaks.practice;

-- name: OwnStreaks :many
SELECT * FROM streaks WHERE user_id = $1 ORDER BY practice;
