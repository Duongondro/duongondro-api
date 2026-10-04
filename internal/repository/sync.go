package repository

import (
	"context"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

// Cursor marks where a client's view of its logs ends: the database generation and
// a transaction id. CodeShare's scheme, unchanged:
//
//   - Every write sets xid = pg_current_xact_id(). The read runs in one
//     REPEATABLE READ snapshot and returns rows with xid >= the cursor; the next
//     cursor is the snapshot's xmin, the oldest transaction still running when it was
//     taken. Rows a later read could add all have xid >= xmin, so none is missed;
//     rows at or above xmin may come twice, which last-write-wins makes harmless.
//   - The generation identifies this database's history. A cursor from another
//     generation (a restored dump, after UPDATE database_generation SET id = uuidv7())
//     or above the snapshot's xmax cannot be trusted: the read is then full.
type Cursor struct {
	Generation uuid.UUID
	Xid        uint64
}

type Changes struct {
	Cursor Cursor
	Full   bool
	Logs   []db.PracticeLog
}

type Sync struct {
	pool *pgxpool.Pool
}

func NewSync(pool *pgxpool.Pool) *Sync { return &Sync{pool: pool} }

// Since returns the user's logs changed since cursor (all of them for nil).
func (r *Sync) Since(ctx context.Context, userID uuid.UUID, cursor *Cursor) (Changes, error) {
	var c Changes
	err := inTx(ctx, r.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(q *db.Queries) error {
		// The first statement takes the snapshot the rest reads from.
		state, err := q.SyncState(ctx)
		if err != nil {
			return err
		}
		var since uint64
		if cursor != nil && cursor.Generation == state.Generation && cursor.Xid <= state.Xmax {
			since = cursor.Xid
		} else {
			c.Full = true
		}
		c.Cursor.Generation = state.Generation
		if c.Cursor.Xid, err = q.SnapshotXmin(ctx); err != nil {
			return err
		}
		c.Logs, err = q.LogsChangedSince(ctx, db.LogsChangedSinceParams{UserID: userID, Since: since})
		return err
	})
	return c, err
}
