package service

import (
	"context"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

// Recovery stores the practice key and identity seed sealed under the recovery code
// (docs/crypto.md, Recovery). Losing every phone then loses nothing; the server
// holds boxes it cannot open.
type Recovery struct {
	q *db.Queries
}

func NewRecovery(pool *pgxpool.Pool) *Recovery { return &Recovery{q: db.New(pool)} }

func (r *Recovery) Put(ctx context.Context, userID uuid.UUID, kind int, box []byte) error {
	if kind != int(e2ee.KindPracticeKey) && kind != int(e2ee.KindIdentitySeed) {
		return invalid("kind must be 1 (practice key) or 2 (identity seed)")
	}
	if len(box) != e2ee.WrappedBoxSize {
		return invalid("box must be %d bytes", e2ee.WrappedBoxSize)
	}
	return r.q.PutRecoveryBox(ctx, db.PutRecoveryBoxParams{UserID: userID, Kind: int16(kind), Box: box})
}

func (r *Recovery) List(ctx context.Context, userID uuid.UUID) ([]db.RecoveryBox, error) {
	return r.q.ListRecoveryBoxes(ctx, userID)
}
