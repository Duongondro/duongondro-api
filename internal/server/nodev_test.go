//go:build !DEV

package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The default build must not contain the dev session route: an omitted tag
// fails safe.
func TestDefaultBuildHasNoDevSession(t *testing.T) {
	if devEnabled {
		t.Fatal("dev route compiled into a default build")
	}
	srv := httptest.NewServer(New(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{}))
	defer srv.Close()
	res, err := http.Post(srv.URL+"/api/dev/session", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /api/dev/session: %d, want 404", res.StatusCode)
	}
}
