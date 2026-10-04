// Package webfs embeds the public website. It lives next to the files it
// embeds because go:embed cannot reach outside the package directory.
package webfs

import "embed"

// FS holds the site. The association files under /.well-known/ are not here: the
// API generates them from its configuration (internal/server/wellknown.go).
//
//go:embed index.html site.css invite.js magic.js favicon.svg robots.txt fonts i f m privacy
var FS embed.FS
