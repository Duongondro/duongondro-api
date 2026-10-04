package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

type Accounts struct {
	q *db.Queries
}

func NewAccounts(pool *pgxpool.Pool) *Accounts {
	return &Accounts{q: db.New(pool)}
}

// SetIdentity stores the user's Ed25519 identity public key, once. Friends pin it, so
// it never changes; sending the same key again is a no-op.
func (a *Accounts) SetIdentity(ctx context.Context, user db.User, key []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return invalid("publicKey must be a %d-byte Ed25519 public key", ed25519.PublicKeySize)
	}
	if user.IdentityPublicKey != nil {
		if bytes.Equal(user.IdentityPublicKey, key) {
			return nil
		}
		return conflict("the identity key is already set and never changes")
	}
	n, err := a.q.SetIdentityKey(ctx, db.SetIdentityKeyParams{IdentityPublicKey: key, ID: user.ID})
	if err != nil {
		return fmt.Errorf("set identity key: %w", err)
	}
	if n == 0 {
		// Another request set it first; same answer as above against the stored key.
		stored, err := a.q.GetUser(ctx, user.ID)
		if err != nil {
			return err
		}
		if !bytes.Equal(stored.IdentityPublicKey, key) {
			return conflict("the identity key is already set and never changes")
		}
	}
	return nil
}
