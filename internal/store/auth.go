package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateMagicLink stores the hash of a sign-in token and drops expired
// links, so unauthenticated requests cannot grow the table without bound.
func (s *Store) CreateMagicLink(ctx context.Context, hash []byte, email string, expires time.Time) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM magic_links WHERE expires_at < now() - interval '1 day'`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO magic_links (token_hash, email, expires_at) VALUES ($1, $2, $3)`, hash, email, expires)
	return err
}

// ConsumeMagicLink marks an unexpired, unused link as used and returns its
// address. ErrNotFound covers unknown, expired and used links alike.
func (s *Store) ConsumeMagicLink(ctx context.Context, hash []byte) (string, error) {
	var email string
	err := s.pool.QueryRow(ctx, `UPDATE magic_links SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING email`, hash).Scan(&email)
	return email, notFound(err)
}

// UserByEmail finds the account with a verified email identity.
func (s *Store) UserByEmail(ctx context.Context, email string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT user_id::text FROM auth_identities
		WHERE provider = 'email' AND subject = $1`, email).Scan(&id)
	return id, notFound(err)
}

// CreateSignupToken stores a pending sign-up for an address with no account.
func (s *Store) CreateSignupToken(ctx context.Context, hash []byte, email string, expires time.Time) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM signup_tokens WHERE expires_at < now() - interval '1 day'`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO signup_tokens (token_hash, email, expires_at) VALUES ($1, $2, $3)`, hash, email, expires)
	return err
}

// consumeSignupToken marks a pending sign-up as used inside tx.
func consumeSignupToken(ctx context.Context, tx pgx.Tx, hash []byte) (string, error) {
	var email string
	err := tx.QueryRow(ctx, `UPDATE signup_tokens SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING email`, hash).Scan(&email)
	return email, notFound(err)
}

// CreateSession stores the hash of a new bearer token.
func (s *Store) CreateSession(ctx context.Context, hash []byte, userID string) error {
	return createSession(ctx, s.pool, hash, userID)
}

func createSession(ctx context.Context, q querier, hash []byte, userID string) error {
	_, err := q.Exec(ctx, `INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)`, hash, userID)
	return err
}

// Session is an authenticated bearer token.
type Session struct {
	UserID   string
	DeviceID string // empty until the session registers a device
}

// SessionByHash resolves a bearer token and records that it was used (at
// most once a minute, to keep reads cheap).
func (s *Store) SessionByHash(ctx context.Context, hash []byte) (Session, error) {
	var out Session
	var device *string
	err := s.pool.QueryRow(ctx, `UPDATE sessions SET last_seen_at = CASE
			WHEN last_seen_at < now() - interval '1 minute' THEN now() ELSE last_seen_at END
		WHERE token_hash = $1
		RETURNING user_id::text, device_id::text`, hash).Scan(&out.UserID, &device)
	if device != nil {
		out.DeviceID = *device
	}
	return out, notFound(err)
}

// DeleteSession revokes one bearer token.
func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hash)
	return err
}

// User is an account as the API shows it.
type User struct {
	ID          string
	DisplayName string
	AvatarRef   *string
	IdentityPK  []byte
	KeyVersion  int32
	CreatedAt   time.Time
}

// GetUser returns a non-placeholder account.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return getUser(ctx, s.pool, id)
}

func getUser(ctx context.Context, q querier, id string) (User, error) {
	var u User
	err := q.QueryRow(ctx, `SELECT id::text, display_name, avatar_ref, identity_pk, key_version, created_at
		FROM users WHERE id = $1 AND NOT placeholder`, id).
		Scan(&u.ID, &u.DisplayName, &u.AvatarRef, &u.IdentityPK, &u.KeyVersion, &u.CreatedAt)
	return u, notFound(err)
}

// UserUpdate holds the fields PATCH /api/me may change; nil means unchanged.
type UserUpdate struct {
	DisplayName *string
	SetAvatar   bool
	AvatarRef   *string
}

// UpdateUser applies u and returns the account.
func (s *Store) UpdateUser(ctx context.Context, id string, u UserUpdate) (User, error) {
	_, err := s.pool.Exec(ctx, `UPDATE users SET
			display_name = COALESCE($2, display_name),
			avatar_ref = CASE WHEN $3 THEN $4 ELSE avatar_ref END
		WHERE id = $1 AND NOT placeholder`, id, u.DisplayName, u.SetAvatar, u.AvatarRef)
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// CreateUser makes an account directly. Only the DEV session route and tests
// use it; real accounts are created by RedeemInviteSignup.
func (s *Store) CreateUser(ctx context.Context, id, displayName string, identityPK []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO users (id, display_name, identity_pk) VALUES ($1, $2, $3)`, id, displayName, identityPK)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// AddEmailIdentity links a verified address to an account.
func (s *Store) AddEmailIdentity(ctx context.Context, userID, email string) error {
	return addEmailIdentity(ctx, s.pool, userID, email)
}

func addEmailIdentity(ctx context.Context, q querier, userID, email string) error {
	_, err := q.Exec(ctx, `INSERT INTO auth_identities (user_id, provider, subject, email, email_verified)
		VALUES ($1, 'email', $2, $2, true)`, userID, email)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}
