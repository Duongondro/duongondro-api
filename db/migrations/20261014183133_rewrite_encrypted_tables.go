package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
)

// rewrittenTables held plain personal values before encryption at rest.
var rewrittenTables = []string{
	"users", "devices", "device_lists", "invites", "invite_redemptions", "reports", "streaks", "credentials",
	"webauthn_sessions", "auth_identities", "magic_links", "push_tokens",
}

// RewriteEncryptedTables is step 3 of encryption at rest. A dropped column's values,
// and the row versions step 2's updates left behind, stay in a table's files until
// the table is rewritten; VACUUM FULL rewrites each table that held plain personal
// values, so they no longer sit in its live files. It does not reach copies elsewhere:
// WAL until it is recycled, archives or physical backups if any, freed blocks on the
// disk, and older dumps until they expire.
//
// VACUUM cannot run in a transaction, so this is a Go migration without one, on one
// connection, so lock_timeout applies to every VACUUM. The service is stopped while
// `server migrate` runs, but a backup's pg_dump may hold a table: a table that cannot
// be locked within lockTimeout is skipped with a warning (the encrypted columns are
// already committed; only the rewrite waits), and `VACUUM FULL <table>` can be run by
// hand later.
func RewriteEncryptedTables(lockTimeout time.Duration) *goose.Migration {
	return goose.NewGoMigration(20261014183133,
		&goose.GoFunc{RunDB: func(ctx context.Context, db *sql.DB) error { return rewrite(ctx, db, lockTimeout) }},
		nil) // never rolled back; fix forward, like the SQL migrations
}

func rewrite(ctx context.Context, db *sql.DB, lockTimeout time.Duration) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET lock_timeout = %d", lockTimeout.Milliseconds())); err != nil {
		return err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "RESET lock_timeout")
	for _, table := range rewrittenTables {
		_, err := conn.ExecContext(ctx, "VACUUM FULL "+table)
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "55P03" { // lock_not_available
			slog.WarnContext(ctx, "VACUUM FULL skipped: the table was locked; run it by hand", "table", table)
			continue
		}
		if err != nil {
			return fmt.Errorf("VACUUM FULL %s: %w", table, err)
		}
	}
	return nil
}
