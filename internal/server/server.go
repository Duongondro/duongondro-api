// Package server wires the HTTP routes of api/openapi.yaml onto net/http's
// ServeMux. Handlers follow the contract by hand (docs/stack.md). Every API
// route lives under /api/ so the website, mounted at "/" as a catch-all,
// never swallows one.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Duongondro/duongondro-api/internal/buildinfo"
	"github.com/Duongondro/duongondro-api/internal/push"
	"github.com/Duongondro/duongondro-api/internal/store"
	"github.com/Duongondro/duongondro-api/internal/web"
)

// MaxBodyBytes caps every request body, as CodeShare does.
const MaxBodyBytes = 64 << 10

// Deps are the server's collaborators. Zero values get safe defaults that
// log instead of sending.
type Deps struct {
	Store        *store.Store
	Mail         EmailSender
	Push         push.Sender
	AppleRevoker SignInWithAppleRevoker
	// MagicLinkBase is prefixed to the token in sign-in mails; the token
	// goes in the fragment so browsers never send it to a server.
	MagicLinkBase string
	Now           func() time.Time
}

// Server holds the handlers' state.
type Server struct {
	log      *slog.Logger
	store    *store.Store
	mail     EmailSender
	push     push.Sender
	revoker  SignInWithAppleRevoker
	linkBase string
	now      func() time.Time
	limits   *limits
}

// New returns the HTTP handler.
func New(log *slog.Logger, deps Deps) http.Handler {
	s := &Server{
		log:      log,
		store:    deps.Store,
		mail:     deps.Mail,
		push:     deps.Push,
		revoker:  deps.AppleRevoker,
		linkBase: deps.MagicLinkBase,
		now:      deps.Now,
	}
	if s.mail == nil {
		s.mail = LogSender{Log: log}
	}
	if s.push == nil {
		s.push = push.LogSender{Log: log}
	}
	if s.revoker == nil {
		s.revoker = NoopRevoker{}
	}
	if s.linkBase == "" {
		s.linkBase = "https://duongondro.app/m#"
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.limits = newLimits(s.now)
	return s.routes()
}

func (s *Server) routes() http.Handler {
	info := buildinfo.Read()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, info)
	})

	// Auth and account.
	mux.HandleFunc("POST /api/auth/magic-link", s.requestMagicLink)
	mux.HandleFunc("POST /api/auth/magic-link/verify", s.verifyMagicLink)
	mux.HandleFunc("GET /api/me", s.authed(s.getMe))
	mux.HandleFunc("PATCH /api/me", s.authed(s.updateMe))
	mux.HandleFunc("DELETE /api/me/session", s.authed(s.signOut))
	registerDev(s, mux)

	// Unknown /api/ paths answer JSON 404 (405 for a known path with
	// another method) instead of reaching the website.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		var allow []string
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, p := mux.Handler(probe); p != "/api/" {
				allow = append(allow, m)
			}
		}
		if len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not_found")
	})
	// Everything else is the public website: landing page, invite and
	// add-friend link pages, privacy policy, .well-known files.
	mux.Handle("/", web.Handler())
	return withBasics(s.log, mux)
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
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
