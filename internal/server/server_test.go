package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutes(t *testing.T) {
	srv := httptest.NewServer(New(slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/healthz")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", err, res)
	}

	res, err = http.Get(srv.URL + "/api/version")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("version: %v %v", err, res)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"revision", "short", "modified", "go"} {
		if _, ok := body[k]; !ok {
			t.Errorf("version response lacks %q: %v", k, body)
		}
	}

	res, err = http.Get(srv.URL + "/.well-known/apple-app-site-association")
	if err != nil || res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("aasa: %v %v", err, res)
	}

	res, err = http.Post(srv.URL+"/api/version", "application/json", nil)
	if err != nil || res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST version should be 405: %v %v", err, res.StatusCode)
	}
}
