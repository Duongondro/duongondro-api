// Package web serves the public website (landing page, privacy draft, invite
// and add-friend pages, app-link association files) from the embedded files in
// the top-level web directory, and the counted download links (download.go).
package web

import (
	"bytes"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	webfs "github.com/Duongondro/duongondro-api/web"
)

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const (
	cacheNone      = "no-store"
	cachePage      = "public, max-age=300"
	cacheAssets    = "public, max-age=604800"
	cacheImmutable = "public, max-age=31536000, immutable"
)

// Handler returns the website handler. It serves GET and HEAD only, except for
// the POST that counts a download in downloads (download.go).
func Handler(downloads Downloads) http.Handler {
	return handler{files: webfs.FS, downloads: downloads}
}

type handler struct {
	files     fs.FS
	downloads Downloads
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", csp)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")

	p := r.URL.Path
	// The download links check their own methods: the count also takes a POST.
	if strings.HasPrefix(p, "/download/") {
		h.serveDownload(w, r, strings.TrimPrefix(p, "/download/"))
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.Contains(p, "\\") {
		http.NotFound(w, r)
		return
	}

	// Invite and add-friend links: the same page for every id. The secret is
	// in the fragment, which browsers never send, so the server cannot see it.
	// QR codes carry the path upper case (/I/, /F/), so either case.
	lower := strings.ToLower(p)
	for _, dir := range []string{"i", "f"} {
		if lower == "/"+dir+"/" || strings.HasPrefix(lower, "/"+dir+"/") {
			h.serve(w, r, dir+"/index.html", cacheNone)
			return
		}
	}
	// Magic sign-in links (/m#<token>) open in the app; the page is the
	// fallback when they reach a browser.
	if p == "/m" || p == "/m/" || strings.HasPrefix(p, "/m/") {
		h.serve(w, r, "m/index.html", cacheNone)
		return
	}
	if p == "/privacy" {
		http.Redirect(w, r, "/privacy/", http.StatusMovedPermanently)
		return
	}

	name := strings.TrimPrefix(path.Clean(p), "/")
	if name == "" {
		name = "index.html"
	} else if strings.HasSuffix(p, "/") {
		name += "/index.html"
	}
	h.serve(w, r, name, cacheFor(name))
}

func cacheFor(name string) string {
	switch {
	// Astro's build output carries a content hash in every name under _assets/,
	// and the fonts never change under one name.
	case strings.HasPrefix(name, "_assets/"), strings.HasPrefix(name, "fonts/"):
		return cacheImmutable
	case strings.HasSuffix(name, ".html"):
		return cachePage
	default:
		return cacheAssets
	}
}

func (h handler) serve(w http.ResponseWriter, r *http.Request, name, cache string) {
	b, err := fs.ReadFile(h.files, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	hd := w.Header()
	hd.Set("Cache-Control", cache)
	hd.Set("Content-Type", contentType(name))
	if cache == cacheNone {
		hd.Set("Pragma", "no-cache")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".woff"):
		return "font/woff"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(name, ".txt"):
		return "text/plain; charset=utf-8"
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
