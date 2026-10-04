// Package webfs embeds the public website. It lives next to the files it
// embeds because go:embed cannot reach outside the package directory.
package webfs

import "embed"

// FS holds the site. The patterns name .well-known explicitly: a plain
// "//go:embed web" or a glob would skip dot-directories.
//
//go:embed index.html site.css invite.js magic.js favicon.svg robots.txt fonts i f m privacy .well-known
var FS embed.FS
