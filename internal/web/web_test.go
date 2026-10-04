package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func checkSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "http") || strings.Contains(csp, "unsafe") {
		t.Errorf("CSP = %q", csp)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("nosniff missing")
	}
	if h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", h.Get("Referrer-Policy"))
	}
}

func TestRoutes(t *testing.T) {
	tests := []struct {
		path, contains, cache string
	}{
		{"/", "Track your meditation practice together with your friends.", "public, max-age=300"},
		{"/privacy/", "Draft — not yet in force", "public, max-age=300"},
		{"/i/7K2MQ9XA", "You have been invited", "no-store"},
		{"/i/", "You have been invited", "no-store"},
		{"/f/7K2MQ9XA", "Add a friend", "no-store"},
		{"/m", "Open this link on your phone", "no-store"},
		{"/m/", "Open this link on your phone", "no-store"},
		{"/magic.js", "replaceState", "public, max-age=604800"},
		{"/site.css", "--ground", "public, max-age=604800"},
		{"/invite.js", "location.hash", "public, max-age=604800"},
		{"/favicon.svg", "<svg", "public, max-age=604800"},
		{"/robots.txt", "Disallow: /i/", "public, max-age=604800"},
		{"/fonts/ibm-plex-sans-regular-latin1.woff2", "", "public, max-age=31536000, immutable"},
		{"/I/7K2MQ9XA", "You have been invited", "no-store"},
		{"/F/7K2MQ9XA", "Add a friend", "no-store"},
	}
	for _, tc := range tests {
		rec := get(t, http.MethodGet, tc.path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", tc.path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.contains) {
			t.Errorf("%s: body lacks %q", tc.path, tc.contains)
		}
		if got := rec.Header().Get("Cache-Control"); got != tc.cache {
			t.Errorf("%s: Cache-Control = %q, want %q", tc.path, got, tc.cache)
		}
		checkSecurityHeaders(t, rec)
	}
}

func TestInvitePagesDoNotLeak(t *testing.T) {
	for _, p := range []string{"/i/3Q8W5E7R", "/f/3Q8W5E7R", "/m/3Q8W5E7R"} {
		rec := get(t, http.MethodGet, p)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: Content-Type = %q", p, ct)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: not no-store", p)
		}
		if strings.Contains(rec.Body.String(), "3Q8W5E7R") {
			t.Errorf("%s: page echoes the id", p)
		}
	}
}

func TestNotFoundAndMethods(t *testing.T) {
	for _, p := range []string{"/nope", "/README.md", "/fonts/", "/web.go", "/i/../README.md", "/embed.go"} {
		rec := get(t, http.MethodGet, p)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", p, rec.Code)
		}
		checkSecurityHeaders(t, rec)
	}
	rec := get(t, http.MethodPost, "/")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d", rec.Code)
	}
	checkSecurityHeaders(t, rec)
	if rec := get(t, http.MethodHead, "/i/ABC"); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	rec = get(t, http.MethodGet, "/privacy")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/privacy/" {
		t.Errorf("/privacy: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestNoExternalOrigins(t *testing.T) {
	for _, p := range []string{"/", "/privacy/", "/i/x", "/f/x", "/site.css", "/invite.js"} {
		body := get(t, http.MethodGet, p).Body.String()
		for _, bad := range []string{"src=\"http", "href=\"http://", "url(http", "@import", "fonts.googleapis", "style=\""} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", p, bad)
			}
		}
	}
}
