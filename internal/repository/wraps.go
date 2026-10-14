package repository

import (
	"context"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
)

// ErrStaleRotation means another rotation moved the version first.
var ErrStaleRotation = errors.New("the practice key was rotated concurrently")

type Wraps struct {
	pool *pgxpool.Pool
	keys *atrest.Keys
}

func NewWraps(pool *pgxpool.Pool, keys *atrest.Keys) *Wraps { return &Wraps{pool: pool, keys: keys} }

// Rotate locks the user, lets check turn the request into wraps against the locked
// row and the devices holding the current key, stores them and bumps the version,
// all in one transaction.
func (r *Wraps) Rotate(ctx context.Context, userID uuid.UUID, newVersion int,
	check func(locked atrest.User, holders []atrest.Device) ([]db.PutWrapParams, error)) error {
	return inTx(ctx, r.pool, pgx.TxOptions{}, func(q *db.Queries) error {
		user, err := r.keys.User(q.LockUser(ctx, userID))
		if err != nil {
			return err
		}
		holders, err := r.keys.PracticeKeyHolders(q.PracticeKeyHolders(ctx, db.PracticeKeyHoldersParams{UserID: userID, KeyVersion: user.KeyVersion}))
		if err != nil {
			return err
		}
		wraps, err := check(user, holders)
		if err != nil {
			return err
		}
		for _, w := range wraps {
			if err := q.PutWrap(ctx, w); err != nil {
				return err
			}
		}
		n, err := q.SetKeyVersion(ctx, db.SetKeyVersionParams{ID: userID, NewVersion: int32(newVersion)})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrStaleRotation
		}
		return nil
	})
}
