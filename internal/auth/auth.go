// Package auth issues and checks session tokens. The sign-in methods (passkeys,
// Sign in with Apple, Google, magic links) all end here, in a bearer token stored
// as its SHA-256, as in CodeShare. Signing in never grants keys: a new device still
// enrols from an existing one or the recovery code.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

type Service struct {
	q *db.Queries
}

func New(pool *pgxpool.Pool) *Service {
	return &Service{q: db.New(pool)}
}

// ErrInvalidToken means the token is not a live session: never issued, or revoked.
// Only this may become a 401. The apps sign out on a 401, so a database hiccup
// reported as one would sign out every device that happened to check in.
var ErrInvalidToken = errors.New("invalid session token")

// hashToken is what the sessions table stores instead of the token itself.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewSession starts a session for the user and returns its token.
func (s *Service) NewSession(ctx context.Context, userID uuid.UUID) (string, error) {
	token, err := RandomToken()
	if err != nil {
		return "", err
	}
	if err := s.q.CreateSession(ctx, db.CreateSessionParams{TokenHash: hashToken(token), UserID: userID}); err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// SessionUser returns the owner of a live session, or ErrInvalidToken.
func (s *Service) SessionUser(ctx context.Context, token string) (db.User, error) {
	row, err := s.q.GetSessionUser(ctx, hashToken(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return row, ErrInvalidToken
	}
	return row, err
}

// RevokeToken deletes the session, reporting whether it existed. Sessions never
// expire, so signing out is the only way one ends.
func (s *Service) RevokeToken(ctx context.Context, token string) (bool, error) {
	n, err := s.q.DeleteSession(ctx, hashToken(token))
	return n > 0, err
}

// RandomToken returns 32 random bytes, base64url-encoded.
func RandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BearerPrefix extracts the token from an "Authorization: Bearer <token>" value. A
// token that isn't ValidText can't be one we issued, and is refused like a missing one.
func BearerPrefix(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return "", false
	}
	token := header[len(prefix):]
	if !ValidText(token) {
		return "", false
	}
	return token, true
}

// ValidText reports whether Postgres can store s as text: valid UTF-8 without NUL.
func ValidText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false
		}
	}
	return true
}
