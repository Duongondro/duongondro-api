// Package db opens the PostgreSQL pool and applies the embedded migrations.
//
// Migrations are plain SQL files in migrations/, applied in name order, each
// in its own transaction and recorded in schema_migrations. A shipped
// migration is never edited; a change is a new file.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open connects to url and checks the connection.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	return OpenConfig(ctx, cfg)
}

// OpenConfig connects with a prepared configuration.
func OpenConfig(ctx context.Context, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Migration is one embedded SQL file.
type Migration struct {
	Version string // file name without .sql
	SQL     string
}

// Migrations lists the embedded migrations in the order they apply.
func Migrations() ([]Migration, error) {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]Migration, 0, len(names))
	for _, n := range names {
		b, err := migrations.ReadFile(n)
		if err != nil {
			return nil, err
		}
		v := strings.TrimSuffix(strings.TrimPrefix(n, "migrations/"), ".sql")
		out = append(out, Migration{Version: v, SQL: string(b)})
	}
	return out, nil
}

// migrateLock is the advisory lock key that serialises concurrent migrators.
const migrateLock = 0x6475_6f6e // "duon"

// Migrate applies every migration not yet recorded, each in its own
// transaction, and returns the versions it applied.
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	all, err := Migrations()
	if err != nil {
		return nil, err
	}
	var applied []string
	for _, m := range all {
		done, err := apply(ctx, pool, m)
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.Version, err)
		}
		if done {
			applied = append(applied, m.Version)
		}
	}
	return applied, nil
}

func apply(ctx context.Context, pool *pgxpool.Pool, m Migration) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(migrateLock)); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.Version).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	// No arguments: pgx sends the file with the simple protocol, so it may
	// hold several statements.
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.Version); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// Tx runs fn in a transaction with the given options, committing if fn
// returns nil and rolling back otherwise.
func Tx(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
