// Package migrations embeds the goose migrations. Create new ones with
// `make db-new name=<snake_case>`, never by numbering them by hand.
//
// Go migrations (a <version>_<name>.go file here) need the keys of encryption at
// rest, so they are constructed with them and handed to goose by Go, below, rather
// than registered globally.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/Duongondro/duongondro-api/internal/atrest"
)

// FS holds every .sql file here, as sqlc reads them for the schema.
//
//go:embed *.sql
var FS embed.FS

// runByGo are .sql files a Go migration runs inside its own transaction; goose must
// not run them again. They stay .sql files, in version order, so sqlc sees the schema
// they make.
var runByGo = map[string]bool{dropPlainColumns: true}

const dropPlainColumns = "20261014183132_drop_plain_columns.sql"

// GooseFS is FS without the files a Go migration runs: what goose applies.
func GooseFS() fs.FS { return hidden{FS} }

// Go returns the Go migrations, sealing under keys.
func Go(keys *atrest.Keys) []*goose.Migration {
	return []*goose.Migration{EncryptColumnsBackfill(keys), RewriteEncryptedTables(10 * time.Second)}
}

type hidden struct{ fsys embed.FS }

func (h hidden) Open(name string) (fs.File, error) {
	if runByGo[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return h.fsys.Open(name)
}

func (h hidden) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := h.fsys.ReadDir(name)
	var out []fs.DirEntry
	for _, e := range entries {
		if !runByGo[e.Name()] {
			out = append(out, e)
		}
	}
	return out, err
}

// dropPlainColumnsUp is the Up section of the drop migration.
func dropPlainColumnsUp() (string, error) {
	raw, err := FS.ReadFile(dropPlainColumns)
	if err != nil {
		return "", err
	}
	_, up, ok := strings.Cut(string(raw), "-- +goose Up")
	if !ok {
		return "", fmt.Errorf("%s has no Up section", dropPlainColumns)
	}
	up, _, _ = strings.Cut(up, "-- +goose Down")
	return up, nil
}
