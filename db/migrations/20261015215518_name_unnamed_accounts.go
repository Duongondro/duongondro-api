package migrations

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/pressly/goose/v3"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/service/names"
)

// NameUnnamedAccounts gives every account without a display name a random English
// one ("Tidy Otter"), as sign-up has since the owner decided on anonymous names, so
// that the unnamed push keys are reached only by someone who clears their name later
// (an app without those strings would show a raw key or a blank). A name counts as
// missing when the column is NULL or names.Clean leaves nothing of it. The name is
// sealed like any display name, which is why this is a Go migration: `server migrate`
// runs it with SECRET_KEY_BASE, before the server starts. Only the count is logged.
func NameUnnamedAccounts(keys *atrest.Keys) *goose.Migration {
	return goose.NewGoMigration(20261015215518,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			n, err := nameUnnamed(ctx, tx, keys)
			if err == nil {
				slog.InfoContext(ctx, "Named accounts without a display name", "count", n)
			}
			return err
		}},
		nil) // never rolled back; fix forward, like the SQL migrations
}

// nameUnnamed is idempotent: an account with a name is left alone.
func nameUnnamed(ctx context.Context, tx *sql.Tx, k *atrest.Keys) (int, error) {
	type user struct {
		id     string
		sealed []byte
	}
	all, err := rows(ctx, tx, `SELECT id::text, display_name_encrypted FROM users`, func(r *sql.Rows) (u user, err error) {
		return u, r.Scan(&u.id, &u.sealed)
	})
	if err != nil {
		return 0, err
	}
	named := 0
	for _, u := range all {
		id, err := parseID(u.id)
		if err != nil {
			return named, err
		}
		row := atrest.IDRow(id)
		if u.sealed != nil {
			name, err := k.OpenString(atrest.UsersDisplayName, row, u.sealed)
			if err != nil {
				return named, err
			}
			if names.Clean(name) != "" {
				continue
			}
		}
		name, err := names.Random()
		if err != nil {
			return named, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name_encrypted = $2 WHERE id = $1`,
			u.id, k.SealString(atrest.UsersDisplayName, row, name)); err != nil {
			return named, err
		}
		named++
	}
	return named, nil
}
