// Package dbtest gives integration tests a freshly migrated database.
package dbtest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/migrate"
)

// Fresh connects to TEST_DATABASE_URL with search_path set to schema, drops and
// recreates that schema and migrates it. It skips the test when the variable is
// unset and refuses databases without "test" in the name.
//
// As in CodeShare, each test package passes a schema of its own, because go test
// runs packages in parallel against the same database.
func Fresh(t testing.TB, schema string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if name := config.ConnConfig.Database; !strings.Contains(name, "test") {
		t.Fatalf("refusing to wipe database %q: its name must contain \"test\"", name)
	}
	ident := pgx.Identifier{schema}.Sanitize()
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+ident+" CASCADE; CREATE SCHEMA "+ident); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}
