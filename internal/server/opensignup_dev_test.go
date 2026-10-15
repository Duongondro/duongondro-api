//go:build DEV

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/dbtest"
	"github.com/Duongondro/duongondro-api/internal/oidc"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// echoVerifier accepts a token "<subject> <nonce>" for that subject and nonce.
type echoVerifier struct{}

func (echoVerifier) Verify(_ context.Context, raw string) (oidc.Claims, error) {
	sub, nonce, ok := strings.Cut(raw, " ")
	if !ok {
		return oidc.Claims{}, oidc.ErrInvalidToken
	}
	return oidc.Claims{Subject: sub, Nonce: nonce}, nil
}

type nullMailer struct{}

func (nullMailer) SendMagicLink(context.Context, string, string, string) error { return nil }

func newSignUpServer(t *testing.T, schema string, open bool) *echo.Echo {
	t.Helper()
	e, _, err := New(dbtest.Fresh(t, schema), Config{Keys: dbtest.Keys(),
		SignIn: service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"},
			Verifiers: map[string]service.TokenVerifier{"google": echoVerifier{}}, Mailer: nullMailer{}, OpenSignUp: open},
		MagicLinkBase: "https://duongondro.app/m#",
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// errorOf checks a response is {"error": "..."}, the shape of every 4xx with a body.
func errorOf(t *testing.T, body []byte) string {
	t.Helper()
	var out struct{ Error string }
	if err := json.Unmarshal(body, &out); err != nil || out.Error == "" {
		t.Fatalf("not an error body: %s", body)
	}
	return out.Error
}

func TestOpenSignUpOverHTTP(t *testing.T) {
	signUp := map[string]any{"signUp": true, "consent": true}

	t.Run("off", func(t *testing.T) {
		e := newSignUpServer(t, "server_open_off_tests", false)
		rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", signUp)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("open passkey sign-up while off: %d %s", rec.Code, rec.Body)
		}
		errorOf(t, rec.Body.Bytes())
		if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", map[string]any{}); rec.Code != http.StatusBadRequest {
			t.Fatalf("no proof, no flag: %d %s", rec.Code, rec.Body)
		}
		if rec := serve(t, e, http.MethodPost, "/api/auth/magic-links", "", map[string]any{"email": "a@example.com", "signUp": true, "consent": true}); rec.Code != http.StatusForbidden {
			t.Fatalf("open magic link while off: %d %s", rec.Code, rec.Body)
		}
		if rec := serve(t, e, http.MethodPost, "/api/auth/magic-links", "", map[string]any{"email": "a@example.com"}); rec.Code != http.StatusNoContent {
			t.Fatalf("plain magic link: %d %s", rec.Code, rec.Body)
		}
		if rec := google(t, e, "g-off", signUp); rec.Code != http.StatusForbidden {
			t.Fatalf("open Google sign-up while off: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("on", func(t *testing.T) {
		e := newSignUpServer(t, "server_open_on_tests", true)
		// Android 0.3's request, unchanged: an admission code, no flag.
		if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", map[string]any{"admissionCode": "zzzz-zzzz-zzzz-zzzz"}); rec.Code != http.StatusNotFound {
			t.Fatalf("unknown admission code: %d %s", rec.Code, rec.Body)
		}
		if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", map[string]any{"signUp": true}); rec.Code != http.StatusBadRequest {
			t.Fatalf("no consent: %d %s", rec.Code, rec.Body)
		}
		if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", signUp); rec.Code != http.StatusOK {
			t.Fatalf("open passkey sign-up: %d %s", rec.Code, rec.Body)
		}
		if rec := google(t, e, "g-noflag", nil); rec.Code != http.StatusForbidden {
			t.Fatalf("Google without the flag: %d %s", rec.Code, rec.Body)
		}
		for i := range service.OpenSignUpLimit {
			rec := google(t, e, "g-"+string(rune('a'+i)), signUp)
			var out struct{ Created bool }
			if _ = json.Unmarshal(rec.Body.Bytes(), &out); rec.Code != http.StatusOK || !out.Created {
				t.Fatalf("open Google sign-up %d: %d %s", i+1, rec.Code, rec.Body)
			}
		}
		rec := google(t, e, "g-over", signUp)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("over the limit: %d %s", rec.Code, rec.Body)
		}
		if msg := errorOf(t, rec.Body.Bytes()); msg != service.ErrSignUpRateLimited.Error() {
			t.Fatalf("over the limit: %s", msg)
		}
		rec = serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", signUp)
		if msg := errorOf(t, rec.Body.Bytes()); rec.Code != http.StatusTooManyRequests || msg != service.ErrSignUpRateLimited.Error() {
			t.Fatalf("passkey over the limit: %d %s", rec.Code, rec.Body)
		}
		// Another client, as Caddy reports it from loopback, has its own count.
		req := httptest.NewRequest(http.MethodPost, "/api/auth/passkeys/sign-up", strings.NewReader(`{"signUp":true,"consent":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113.77")
		req.RemoteAddr = "127.0.0.1:41000"
		other := httptest.NewRecorder()
		e.ServeHTTP(other, req)
		if other.Code != http.StatusOK {
			t.Fatalf("another client address: %d %s", other.Code, other.Body)
		}
	})
}

// Open magic-link requests are limited per client address, mailed or not.
func TestOpenSignUpMailLimitOverHTTP(t *testing.T) {
	e := newSignUpServer(t, "server_open_mail_tests", true)
	for i := range service.OpenSignUpMailLimit {
		body := map[string]any{"email": fmt.Sprintf("m%d@example.com", i), "signUp": true, "consent": true}
		if rec := serve(t, e, http.MethodPost, "/api/auth/magic-links", "", body); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	rec := serve(t, e, http.MethodPost, "/api/auth/magic-links", "", map[string]any{"email": "over@example.com", "signUp": true, "consent": true})
	if msg := errorOf(t, rec.Body.Bytes()); rec.Code != http.StatusTooManyRequests || msg != service.ErrSignUpMailRateLimited.Error() {
		t.Fatalf("over the limit: %d %s", rec.Code, rec.Body)
	}
}

// google signs in with Google as subject, with extra fields in the body.
func google(t *testing.T, e *echo.Echo, subject string, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := serve(t, e, http.MethodPost, "/api/auth/nonces", "", nil)
	var n struct{ Nonce string }
	if err := json.Unmarshal(rec.Body.Bytes(), &n); err != nil || n.Nonce == "" {
		t.Fatalf("nonce: %d %s", rec.Code, rec.Body)
	}
	body := map[string]any{"idToken": subject + " " + n.Nonce, "nonce": n.Nonce}
	for k, v := range extra {
		body[k] = v
	}
	return serve(t, e, http.MethodPost, "/api/auth/providers/google", "", body)
}

// No log line carries the client's address, sign-ups included.
func TestRequestLogHasNoAddress(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	e := newSignUpServer(t, "server_log_tests", true)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkeys/sign-up", strings.NewReader(`{"signUp":true,"consent":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	req.RemoteAddr = "127.0.0.1:41000"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(buf.String(), "REQUEST") {
		t.Fatalf("%d, log %q", rec.Code, buf.String())
	}
	if strings.Contains(buf.String(), "203.0.113.200") || strings.Contains(buf.String(), "127.0.0.1") || strings.Contains(buf.String(), "remote_ip") {
		t.Fatalf("the log carries the address: %s", buf.String())
	}
}
