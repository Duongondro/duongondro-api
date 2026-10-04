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

// Put stores a box signed by the user's identity key (docs/crypto.md, Recovery), so a
// session alone cannot replace it and quietly break recovery.
func (r *Recovery) Put(ctx context.Context, user db.User, kind int, box, signature []byte) error {
	if kind != int(e2ee.KindPracticeKey) && kind != int(e2ee.KindIdentitySeed) {
		return invalid("kind must be 1 (practice key) or 2 (identity seed)")
	}
	if len(box) != e2ee.WrappedBoxSize {
		return invalid("box must be %d bytes", e2ee.WrappedBoxSize)
	}
	if user.IdentityPublicKey == nil {
		return conflict("set the identity key before storing recovery boxes")
	}
	if !e2ee.VerifyRecoveryBox(user.IdentityPublicKey, e2ee.UUID(user.ID), e2ee.WrapKind(kind), box, signature) {
		return invalid("the box's signature does not verify against the identity key")
	}
	return r.q.PutRecoveryBox(ctx, db.PutRecoveryBoxParams{UserID: user.ID, Kind: int16(kind), Box: box, Signature: signature})
}

func (r *Recovery) List(ctx context.Context, userID uuid.UUID) ([]db.RecoveryBox, error) {
	return r.q.ListRecoveryBoxes(ctx, userID)
}
