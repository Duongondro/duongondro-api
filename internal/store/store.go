// Package store is the repository layer: hand-written SQL against the schema
// in internal/db/migrations. It holds no business rules beyond what a single
// statement or transaction must guarantee; the server validates input first.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

var (
	// ErrNotFound means no row matched (or the caller may not see it).
	ErrNotFound = errors.New("store: not found")
	// ErrConflict means a uniqueness rule refused the write.
	ErrConflict = errors.New("store: conflict")
	// ErrStale means a version, sequence number or clock did not advance.
	ErrStale = errors.New("store: stale")
)

// Store wraps the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New returns a store on pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the pool for tests and maintenance.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return db.Tx(ctx, s.pool, pgx.TxOptions{}, fn)
}

// querier is satisfied by the pool and by transactions.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func isFK(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// millis converts a nullable timestamp for the API.
func millis(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	v := t.UnixMilli()
	return &v
}
