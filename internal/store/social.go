package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Invite errors.
var (
	ErrInviteExpired = errors.New("store: invite expired")
	ErrInviteRevoked = errors.New("store: invite revoked")
	ErrBadAuthKey    = errors.New("store: wrong invite auth key")
	ErrOwnInvite     = errors.New("store: own invite")
	ErrBlocked       = errors.New("store: blocked")
	ErrInvalidToken  = errors.New("store: invalid signup token")
	ErrUserExists    = errors.New("store: user exists")
)

// Invite is a stored signed invite record.
type Invite struct {
	ID          string
	InviterID   string
	AuthKeyHash []byte
	Payload     []byte
	Signature   []byte
	MAC         []byte
	ExpiresAt   time.Time
	CreatedAt   time.Time
	RevokedAt   *time.Time
	Redemptions int
	InviterName string
}

// CreateInvite stores inv; ErrConflict if the id is taken.
func (s *Store) CreateInvite(ctx context.Context, inv Invite) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO invites (id, inviter_id, auth_key_hash, payload, signature, mac, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, inv.ID, inv.InviterID, inv.AuthKeyHash, inv.Payload, inv.Signature, inv.MAC, inv.ExpiresAt)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

const inviteColumns = `i.id, i.inviter_id::text, i.auth_key_hash, i.payload, i.signature, i.mac, i.expires_at, i.created_at, i.revoked_at,
	(SELECT count(*) FROM invite_redemptions r WHERE r.invite_id = i.id), u.display_name`

func scanInvite(row pgx.Row, inv *Invite) error {
	return row.Scan(&inv.ID, &inv.InviterID, &inv.AuthKeyHash, &inv.Payload, &inv.Signature, &inv.MAC,
		&inv.ExpiresAt, &inv.CreatedAt, &inv.RevokedAt, &inv.Redemptions, &inv.InviterName)
}

// GetInvite returns an invite by id, whatever its state.
func (s *Store) GetInvite(ctx context.Context, id string) (Invite, error) {
	var inv Invite
	err := scanInvite(s.pool.QueryRow(ctx, `SELECT `+inviteColumns+` FROM invites i JOIN users u ON u.id = i.inviter_id WHERE i.id = $1`, id), &inv)
	return inv, notFound(err)
}

// ListInvites returns the invites a user created, newest first.
func (s *Store) ListInvites(ctx context.Context, inviter string) ([]Invite, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+inviteColumns+` FROM invites i JOIN users u ON u.id = i.inviter_id
		WHERE i.inviter_id = $1 ORDER BY i.created_at DESC, i.id`, inviter)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Invite, error) {
		var inv Invite
		err := scanInvite(r, &inv)
		return inv, err
	})
}

// RevokeInvite ends one of the inviter's invites; friendships stay.
func (s *Store) RevokeInvite(ctx context.Context, inviter, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE invites SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1 AND inviter_id = $2`, id, inviter)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Redemption is one use of an invite: an edge of the invite tree.
type Redemption struct {
	InviteID            string
	InviterID           string
	InviteeID           string
	AcceptancePayload   []byte
	AcceptanceSignature []byte
	RedeemedAt          time.Time
}

// ListRedemptions returns who redeemed one of the inviter's invites.
func (s *Store) ListRedemptions(ctx context.Context, inviter, inviteID string) ([]Redemption, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM invites WHERE id = $1 AND inviter_id = $2)`, inviteID, inviter).Scan(&ok); err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT invite_id, inviter_id::text, invitee_id::text, acceptance_payload, acceptance_signature, redeemed_at
		FROM invite_redemptions WHERE invite_id = $1 ORDER BY redeemed_at, id`, inviteID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Redemption, error) {
		var x Redemption
		err := r.Scan(&x.InviteID, &x.InviterID, &x.InviteeID, &x.AcceptancePayload, &x.AcceptanceSignature, &x.RedeemedAt)
		return x, err
	})
}

// Acceptance is the invitee's signed statement.
type Acceptance struct {
	Payload   []byte
	Signature []byte
}

// redeem checks the invite and records the redemption and friendship
// inside tx. It returns the inviter.
func redeem(ctx context.Context, tx pgx.Tx, now time.Time, inviteID, invitee string, authKey []byte, acc Acceptance) (string, error) {
	var inviter string
	var hash []byte
	var expires time.Time
	var revoked *time.Time
	err := tx.QueryRow(ctx, `SELECT inviter_id::text, auth_key_hash, expires_at, revoked_at FROM invites WHERE id = $1 FOR SHARE`, inviteID).
		Scan(&inviter, &hash, &expires, &revoked)
	if err != nil {
		return "", notFound(err)
	}
	given := sha256.Sum256(authKey)
	switch {
	case subtle.ConstantTimeCompare(given[:], hash) != 1:
		return "", ErrBadAuthKey
	case revoked != nil:
		return "", ErrInviteRevoked
	case !expires.After(now):
		return "", ErrInviteExpired
	case inviter == invitee:
		return "", ErrOwnInvite
	}
	var blocked bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM blocks
		WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1))`, inviter, invitee).Scan(&blocked); err != nil {
		return "", err
	}
	if blocked {
		return "", ErrBlocked
	}
	if _, err := tx.Exec(ctx, `INSERT INTO invite_redemptions (invite_id, inviter_id, invitee_id, acceptance_payload, acceptance_signature)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (invite_id, invitee_id) DO NOTHING`,
		inviteID, inviter, invitee, acc.Payload, acc.Signature); err != nil {
		return "", err
	}
	return inviter, befriend(ctx, tx, inviter, invitee)
}

// RedeemInvite redeems an invite for an existing account; now decides
// whether it has expired.
func (s *Store) RedeemInvite(ctx context.Context, now time.Time, inviteID, invitee string, authKey []byte, acc Acceptance) (inviter string, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		inviter, err = redeem(ctx, tx, now, inviteID, invitee, authKey, acc)
		return err
	})
	return inviter, err
}

// NewAccount is a sign-up through an invite.
type NewAccount struct {
	UserID      string
	DisplayName string
	IdentityPK  []byte
	SignupHash  []byte // hash of the pending-signup token from a magic link
	SessionHash []byte // hash of the new bearer token
}

// RedeemInviteSignup creates an account from a pending sign-up and redeems
// the invite, all in one transaction: no invite, no account.
func (s *Store) RedeemInviteSignup(ctx context.Context, now time.Time, inviteID string, authKey []byte, acc Acceptance, a NewAccount) (inviter string, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		email, err := consumeSignupToken(ctx, tx, a.SignupHash)
		if errors.Is(err, ErrNotFound) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, display_name, identity_pk) VALUES ($1, $2, $3)`, a.UserID, a.DisplayName, a.IdentityPK); err != nil {
			if isUnique(err) {
				return ErrUserExists
			}
			return err
		}
		if err := addEmailIdentity(ctx, tx, a.UserID, email); err != nil {
			if errors.Is(err, ErrConflict) {
				return ErrUserExists
			}
			return err
		}
		if inviter, err = redeem(ctx, tx, now, inviteID, a.UserID, authKey, acc); err != nil {
			return err
		}
		return createSession(ctx, tx, a.SessionHash, a.UserID)
	})
	return inviter, err
}

// Friend is one side of a friendship as the other side sees it.
type Friend struct {
	UserID      string
	DisplayName string
	AvatarRef   *string
	IdentityPK  []byte
	Since       time.Time
	Blocked     bool // the viewer blocked this friend
}

// ListFriends returns the user's friends.
func (s *Store) ListFriends(ctx context.Context, userID string) ([]Friend, error) {
	rows, err := s.pool.Query(ctx, `SELECT u.id::text, u.display_name, u.avatar_ref, u.identity_pk, f.created_at,
			EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = $1 AND b.blocked_id = u.id)
		FROM friendships f
		JOIN users u ON u.id = CASE WHEN f.user_a = $1 THEN f.user_b ELSE f.user_a END
		WHERE (f.user_a = $1 OR f.user_b = $1) AND NOT u.placeholder
		ORDER BY f.created_at, u.id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Friend, error) {
		var f Friend
		err := r.Scan(&f.UserID, &f.DisplayName, &f.AvatarRef, &f.IdentityPK, &f.Since, &f.Blocked)
		return f, err
	})
}

// Unfriend ends a friendship both ways and drops the share-key wraps the
// two sent each other.
func (s *Store) Unfriend(ctx context.Context, a, b string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM friendships WHERE user_a = LEAST($1::uuid, $2::uuid) AND user_b = GREATEST($1::uuid, $2::uuid)`, a, b)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM wraps WHERE (user_id = $1 AND sender_id = $2) OR (user_id = $2 AND sender_id = $1)`, a, b)
		return err
	})
}

// StreakStatement is a stored signed streak.
type StreakStatement struct {
	UserID    string
	Practice  string
	Seq       int64
	Day       time.Time
	Current   int32
	Longest   int32
	Deadline  time.Time
	Payload   []byte
	Signature []byte
}

// PublishStreak stores st if its seq is higher than the stored one. newDay
// reports whether it names a later practice day than the statement it
// replaced (or there was none). On ErrStale, current is the stored seq.
func (s *Store) PublishStreak(ctx context.Context, st StreakStatement) (newDay bool, current int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var prevDay time.Time
		err := tx.QueryRow(ctx, `SELECT seq, day FROM streak_statements WHERE user_id = $1 AND practice = $2 FOR UPDATE`, st.UserID, st.Practice).
			Scan(&current, &prevDay)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			newDay = true
		case err != nil:
			return err
		case st.Seq <= current:
			return ErrStale
		default:
			newDay = st.Day.After(prevDay)
		}
		_, err = tx.Exec(ctx, `INSERT INTO streak_statements (user_id, practice, seq, day, current, longest, deadline, payload, signature)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (user_id, practice) DO UPDATE SET seq = EXCLUDED.seq, day = EXCLUDED.day, current = EXCLUDED.current,
				longest = EXCLUDED.longest, deadline = EXCLUDED.deadline, payload = EXCLUDED.payload,
				signature = EXCLUDED.signature, updated_at = now()`,
			st.UserID, st.Practice, st.Seq, st.Day, st.Current, st.Longest, st.Deadline, st.Payload, st.Signature)
		current = st.Seq
		return err
	})
	return newDay, current, err
}

// UnpublishStreak deletes a practice's statement.
func (s *Store) UnpublishStreak(ctx context.Context, userID, practice string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM streak_statements WHERE user_id = $1 AND practice = $2`, userID, practice)
	return err
}

// FriendStreaks returns the newest statement per friend and practice,
// hiding anyone blocked in either direction.
func (s *Store) FriendStreaks(ctx context.Context, userID string) ([]StreakStatement, error) {
	rows, err := s.pool.Query(ctx, `SELECT s.user_id::text, s.practice, s.seq, s.day, s.current, s.longest, s.deadline, s.payload, s.signature
		FROM streak_statements s
		JOIN friendships f ON (f.user_a = $1 AND f.user_b = s.user_id) OR (f.user_b = $1 AND f.user_a = s.user_id)
		WHERE NOT EXISTS (SELECT 1 FROM blocks b
			WHERE (b.blocker_id = $1 AND b.blocked_id = s.user_id) OR (b.blocker_id = s.user_id AND b.blocked_id = $1))
		ORDER BY s.user_id, s.practice`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (StreakStatement, error) {
		var st StreakStatement
		err := r.Scan(&st.UserID, &st.Practice, &st.Seq, &st.Day, &st.Current, &st.Longest, &st.Deadline, &st.Payload, &st.Signature)
		return st, err
	})
}

// ConnectedFriends lists the friends of userID with no block either way.
func (s *Store) ConnectedFriends(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT CASE WHEN f.user_a = $1 THEN f.user_b ELSE f.user_a END::text AS friend
		FROM friendships f
		WHERE (f.user_a = $1 OR f.user_b = $1)
		AND NOT EXISTS (SELECT 1 FROM blocks b
			WHERE (b.blocker_id = $1 AND b.blocked_id IN (f.user_a, f.user_b))
			   OR (b.blocked_id = $1 AND b.blocker_id IN (f.user_a, f.user_b)))`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Block is one block the user made.
type Block struct {
	UserID    string
	CreatedAt time.Time
}

// UserExists reports whether id is a real (non-placeholder) account.
func (s *Store) UserExists(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND NOT placeholder)`, id).Scan(&ok)
	return ok, err
}

// BlockUser records a block (idempotent).
func (s *Store) BlockUser(ctx context.Context, blocker, blocked string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, blocker, blocked)
	return err
}

// UnblockUser removes a block (idempotent).
func (s *Store) UnblockUser(ctx context.Context, blocker, blocked string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2`, blocker, blocked)
	return err
}

// ListBlocks returns the blocks a user made.
func (s *Store) ListBlocks(ctx context.Context, blocker string) ([]Block, error) {
	rows, err := s.pool.Query(ctx, `SELECT blocked_id::text, created_at FROM blocks WHERE blocker_id = $1 ORDER BY created_at, blocked_id`, blocker)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Block, error) {
		var b Block
		err := r.Scan(&b.UserID, &b.CreatedAt)
		return b, err
	})
}

// Report files a moderation report.
func (s *Store) Report(ctx context.Context, reporter, reported, reason string, note *string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO reports (reporter_id, reported_id, reason, note) VALUES ($1, $2, $3, $4)`, reporter, reported, reason, note)
	return err
}

// PushToken is a stored device push token.
type PushToken struct {
	DeviceID string
	UserID   string
	Platform string
	Token    string
}

// PutPushToken stores the device's token, moving it away from any other
// device that held it (a phone that changed accounts).
func (s *Store) PutPushToken(ctx context.Context, t PushToken) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM push_tokens WHERE platform = $1 AND token = $2 AND device_id <> $3`, t.Platform, t.Token, t.DeviceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO push_tokens (device_id, user_id, platform, token) VALUES ($1, $2, $3, $4)
			ON CONFLICT (device_id) DO UPDATE SET platform = EXCLUDED.platform, token = EXCLUDED.token, updated_at = now()`,
			t.DeviceID, t.UserID, t.Platform, t.Token)
		return err
	})
}

// DeletePushToken removes the device's token.
func (s *Store) DeletePushToken(ctx context.Context, userID, deviceID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM push_tokens WHERE device_id = $1 AND user_id = $2`, deviceID, userID)
	return err
}

// PushTokens returns the tokens of the given users' devices.
func (s *Store) PushTokens(ctx context.Context, userIDs []string) ([]PushToken, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT device_id::text, user_id::text, platform, token FROM push_tokens
		WHERE user_id = ANY($1::uuid[]) ORDER BY user_id, device_id`, userIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (PushToken, error) {
		var t PushToken
		err := r.Scan(&t.DeviceID, &t.UserID, &t.Platform, &t.Token)
		return t, err
	})
}

// Poke records a nudge for the UTC day; ErrConflict if the sender already
// poked this friend that day.
func (s *Store) Poke(ctx context.Context, sender, recipient string, day time.Time) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO nudges (sender_id, recipient_id, day) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		sender, recipient, utcDate(day))
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// utcDate is the UTC calendar date of t, as midnight UTC for a date column.
func utcDate(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
