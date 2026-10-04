package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/ids"
)

// PracticeLog is a sealed practice session.
type PracticeLog struct {
	ID         string
	UserID     string
	Sealed     []byte
	KeyVersion int32
	UpdatedAt  time.Time // the client's clock, whole milliseconds
	Deleted    bool
}

// ErrKeyVersion means a log was sealed under a key version other than the
// account's current one.
var ErrKeyVersion = errors.New("store: not the current key version")

// PutPracticeLog stores l unless the server holds a newer (or equally new)
// write of the same id: last write wins on the client clock. It returns the
// row held afterwards. ErrKeyVersion comes with the current version;
// ErrNotFound means the id belongs to another user.
func (s *Store) PutPracticeLog(ctx context.Context, l PracticeLog) (out PracticeLog, current int32, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		// FOR SHARE: a concurrent key rotation waits for this write, and this
		// write waits for a rotation in progress.
		if err := tx.QueryRow(ctx, `SELECT key_version FROM users WHERE id = $1 FOR SHARE`, l.UserID).Scan(&current); err != nil {
			return notFound(err)
		}
		if l.KeyVersion != current {
			return ErrKeyVersion
		}
		err := scanLog(tx.QueryRow(ctx, `INSERT INTO practice_logs (id, user_id, sealed, key_version, client_updated_at, deleted)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE SET sealed = EXCLUDED.sealed, key_version = EXCLUDED.key_version,
				client_updated_at = EXCLUDED.client_updated_at, deleted = EXCLUDED.deleted,
				xid = pg_current_xact_id()
			WHERE practice_logs.user_id = EXCLUDED.user_id
				AND practice_logs.client_updated_at < EXCLUDED.client_updated_at
			RETURNING `+logColumns, l.ID, l.UserID, l.Sealed, l.KeyVersion, l.UpdatedAt, l.Deleted), &out)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := scanLog(tx.QueryRow(ctx, `SELECT `+logColumns+` FROM practice_logs WHERE id = $1`, l.ID), &out); err != nil {
				return err
			}
			if out.UserID != l.UserID {
				return ErrNotFound
			}
			return nil
		}
		return err
	})
	return out, current, err
}

const logColumns = `id::text, user_id::text, sealed, key_version, client_updated_at, deleted`

func scanLog(row pgx.Row, l *PracticeLog) error {
	return row.Scan(&l.ID, &l.UserID, &l.Sealed, &l.KeyVersion, &l.UpdatedAt, &l.Deleted)
}

// Cursor is a sync position: the database generation and a transaction id.
type Cursor struct {
	Generation string
	XID        uint64
}

func (c Cursor) String() string { return c.Generation + ":" + strconv.FormatUint(c.XID, 10) }

// ParseCursor reads "<generation>:<xid8>".
func ParseCursor(s string) (Cursor, error) {
	gen, x, ok := strings.Cut(s, ":")
	g, valid := ids.CanonicalUUID(gen)
	n, err := strconv.ParseUint(x, 10, 64)
	if !ok || !valid || err != nil {
		return Cursor{}, fmt.Errorf("store: bad cursor")
	}
	return Cursor{Generation: g, XID: n}, nil
}

// SyncResult is one page of changes.
type SyncResult struct {
	Cursor     Cursor
	Full       bool
	KeyVersion int32
	Logs       []PracticeLog
}

// Sync returns the user's logs written by transactions with ids at or above
// since, read in one REPEATABLE READ read-only transaction. The next cursor
// is the snapshot's xmin: every transaction below it had finished, so its
// writes are in this result, and every transaction that commits later has
// an id at or above it, so the next sync sees it. Some rows repeat, which
// last write wins makes harmless. Without a cursor, with a cursor of another
// generation, or with one ahead of the transaction counter (a restore
// without a new generation), every row is returned with Full set.
func (s *Store) Sync(ctx context.Context, userID string, since *Cursor) (SyncResult, error) {
	var res SyncResult
	err := db.Tx(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var xmin, xmax string
		if err := tx.QueryRow(ctx, `SELECT g.id::text,
				pg_snapshot_xmin(pg_current_snapshot())::text,
				pg_snapshot_xmax(pg_current_snapshot())::text,
				u.key_version
			FROM database_generation g, users u WHERE u.id = $1`, userID).
			Scan(&res.Cursor.Generation, &xmin, &xmax, &res.KeyVersion); err != nil {
			return notFound(err)
		}
		var err error
		if res.Cursor.XID, err = strconv.ParseUint(xmin, 10, 64); err != nil {
			return err
		}
		top, err := strconv.ParseUint(xmax, 10, 64)
		if err != nil {
			return err
		}
		from := uint64(0)
		res.Full = since == nil || since.Generation != res.Cursor.Generation || since.XID > top
		if !res.Full {
			from = since.XID
		}
		rows, err := tx.Query(ctx, `SELECT `+logColumns+` FROM practice_logs
			WHERE user_id = $1 AND xid >= $2::text::xid8 ORDER BY xid, id`, userID, strconv.FormatUint(from, 10))
		if err != nil {
			return err
		}
		res.Logs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (PracticeLog, error) {
			var l PracticeLog
			err := scanLog(r, &l)
			return l, err
		})
		return err
	})
	if res.Logs == nil {
		res.Logs = []PracticeLog{}
	}
	return res, err
}
