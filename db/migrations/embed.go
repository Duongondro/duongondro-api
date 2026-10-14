// Package migrations embeds the goose migrations. Create new ones with
// `make db-new name=<snake_case>`, never by numbering them by hand.
//
// Go migrations (a <version>_<name>.go file here) need the keys of encryption at
// rest, so they are constructed with them and handed to goose by Go, below, rather
// than registered globally.
package migrations

import (
	"embed"

	"github.com/pressly/goose/v3"

	"github.com/Duongondro/duongondro-api/internal/atrest"
)

//go:embed *.sql
var FS embed.FS

// Go returns the Go migrations, sealing under keys.
func Go(keys *atrest.Keys) []*goose.Migration {
	return []*goose.Migration{EncryptColumnsBackfill(keys)}
}
