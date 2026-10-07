// Package webfs embeds the public website. It lives next to the files it
// embeds because go:embed cannot reach outside the package directory.
//
// Everything here but this file and README.md is generated: the build of
// github.com/Duongondro/duongondro-landing, synced in by `make web`.
package webfs

import "embed"

// FS holds the site. The association files under /.well-known/ are not here: the
// API generates them from its configuration (internal/server/wellknown.go).
//
//go:embed index.html favicon.ico favicon-32.png apple-touch-icon.png og.png robots.txt _assets fonts i f m privacy
var FS embed.FS
