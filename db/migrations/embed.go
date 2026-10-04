// Package migrations embeds the goose migrations. Create new ones with
// `make db-new name=<snake_case>`, never by numbering them by hand.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
