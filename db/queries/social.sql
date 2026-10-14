-- name: SetDisplayName :exec
UPDATE users SET display_name_encrypted = $2 WHERE id = $1;

-- name: UsernameTaken :one
SELECT EXISTS (SELECT 1 FROM users WHERE username_hash = $1);

-- name: UpdateProfile :exec
-- Each field changes only when its set_ flag is true; each may be set to NULL (an
-- empty display name is NULL). The username and its hash change together.
UPDATE users SET
    display_name_encrypted = CASE WHEN sqlc.arg(set_display_name)::boolean THEN sqlc.narg(display_name_encrypted)::bytea ELSE display_name_encrypted END,
    username_encrypted = CASE WHEN sqlc.arg(set_username)::boolean THEN sqlc.narg(username_encrypted)::bytea ELSE username_encrypted END,
    username_hash = CASE WHEN sqlc.arg(set_username)::boolean THEN sqlc.narg(username_hash)::bytea ELSE username_hash END,
    gender_encrypted = CASE WHEN sqlc.arg(set_gender)::boolean THEN sqlc.narg(gender_encrypted)::bytea ELSE gender_encrypted END
WHERE id = sqlc.arg(id);

-- name: CreateInviteNode :exec
-- Every account gets a node; parent_id is the inviter's node (NULL for the first
-- members and DEV accounts).
INSERT INTO invite_tree (user_id, parent_id)
VALUES (sqlc.arg(user_id), (SELECT node_id FROM invite_tree WHERE invite_tree.user_id = sqlc.narg(inviter_id)));

-- name: CreateInvite :exec
INSERT INTO invites (id, inviter_id, auth_hash, payload_encrypted, signature, mac, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetLiveInvite :one
SELECT * FROM invites WHERE id = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: ListInvites :many
SELECT * FROM invites WHERE inviter_id = $1 ORDER BY created_at DESC;

-- name: RevokeInvite :execrows
UPDATE invites SET revoked_at = now() WHERE id = $1 AND inviter_id = $2 AND revoked_at IS NULL;

-- name: RecordRedemption :exec
INSERT INTO invite_redemptions (invite_id, invitee_id, payload_encrypted, signature) VALUES ($1, $2, $3, $4)
ON CONFLICT (invite_id, invitee_id) DO NOTHING;

-- name: Befriend :exec
INSERT INTO friendships (user_id, friend_id) VALUES ($1, $2), ($2, $1)
ON CONFLICT DO NOTHING;

-- name: Unfriend :execrows
DELETE FROM friendships WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1);

-- name: ListFriends :many
SELECT users.id, users.display_name_encrypted, users.gender_encrypted, users.identity_public_key_encrypted, friendships.created_at, friendships.notify_done
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

-- name: CreateReport :exec
-- The id is drawn by the caller: the sealed reason is bound to it.
INSERT INTO reports (id, reporter_id, reported_id, reason_encrypted) VALUES ($1, $2, $3, $4);

-- name: PutStreak :execrows
-- Only a higher seq replaces the stored statement.
INSERT INTO streaks (user_id, practice_encrypted, practice_hash, seq, payload_encrypted, signature, deadline_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (user_id, practice_hash) DO UPDATE SET
    practice_encrypted = EXCLUDED.practice_encrypted, seq = EXCLUDED.seq,
    payload_encrypted = EXCLUDED.payload_encrypted, signature = EXCLUDED.signature,
    deadline_at = EXCLUDED.deadline_at, updated_at = now()
WHERE streaks.seq < EXCLUDED.seq;

-- name: DeleteStreak :execrows
DELETE FROM streaks WHERE user_id = $1 AND practice_hash = $2;

-- name: FriendsStreaks :many
-- The service orders each friend's practices by name, once opened.
SELECT streaks.* FROM streaks
JOIN friendships ON friendships.friend_id = streaks.user_id
WHERE friendships.user_id = $1
ORDER BY streaks.user_id;

-- name: OwnStreaks :many
SELECT * FROM streaks WHERE user_id = $1;

-- name: GetStreak :one
SELECT * FROM streaks WHERE user_id = $1 AND practice_hash = $2;
