// Package repository holds the queries that need a transaction: rotating the
// practice key, and the sync read. Single-table work goes through sqlc
// (internal/db) straight from internal/service.
package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

func inTx(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(q *db.Queries) error) error {
	return pgx.BeginTxFunc(ctx, pool, opts, func(tx pgx.Tx) error {
		return fn(db.New(tx))
	})
}

// IsUniqueViolation reports whether err is Postgres's 23505, on the named constraint
// or index if one is given.
func IsUniqueViolation(err error, constraint string) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == "23505" && (constraint == "" || pgErr.ConstraintName == constraint)
}

// IsForeignKeyViolation reports whether err is Postgres's 23503.
func IsForeignKeyViolation(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == "23503"
}
