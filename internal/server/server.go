// Package server wires the HTTP routes. For now: health and version only;
// accounts, sync and the social endpoints follow api/openapi.yaml in phase 3.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Duongondro/duongondro-api/internal/buildinfo"
)

// MaxBodyBytes caps every request body, as CodeShare does.
const MaxBodyBytes = 64 << 10

// New returns the API handler.
func New(log *slog.Logger) http.Handler {
	info := buildinfo.Read()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, info)
	})
	return withBasics(log, mux)
}

func withBasics(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
		// Never log query strings, tokens or bodies (CodeShare's rule).
		log.Debug("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
