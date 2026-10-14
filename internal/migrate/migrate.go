// Package migrate applies the goose migrations embedded from db/migrations, and,
// during a key rotation, reseals the encrypted columns under the new key.
package migrate

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Duongondro/duongondro-api/db/migrations"
	"github.com/Duongondro/duongondro-api/internal/atrest"
)

// Up applies the pending migrations; the Go ones seal under keys. When keys carry a
// previous key (a rotation), it then reseals every value still under that key, so
// the server starts with every row and blind index under the current one.
func Up(ctx context.Context, pool *pgxpool.Pool, keys *atrest.Keys) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS,
		goose.WithGoMigrations(migrations.Go(keys)...))
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for _, r := range results {
		file := "(Go)" // handed to goose by migrations.Go, so without a path
		if r.Source.Path != "" {
			file = filepath.Base(r.Source.Path)
		}
		slog.Info("migrated", "version", r.Source.Version, "file", file)
	}
	if keys.Rotating() {
		n, err := atrest.Reseal(ctx, pool, keys)
		if err != nil {
			return err
		}
		slog.Info("resealed under the current key", "rows", n)
	}
	return nil
}
