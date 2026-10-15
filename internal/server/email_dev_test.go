//go:build DEV

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/dbtest"
	"github.com/Duongondro/duongondro-api/internal/service"
)

type sentMail struct{ kind, to, link, code string }

type chanMailer chan sentMail

func (m chanMailer) SendMagicLink(_ context.Context, to, link, code string) error {
	m <- sentMail{"sign-in", to, link, code}
	return nil
}
func (m chanMailer) SendEmailConfirmation(_ context.Context, to, link, code string) error {
	m <- sentMail{"confirm", to, link, code}
	return nil
}

func (m chanMailer) next(t *testing.T, kind, to string) sentMail {
	t.Helper()
	select {
	case got := <-m:
		if got.kind != kind || got.to != to {
			t.Fatalf("mail %+v, want %s to %s", got, kind, to)
		}
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("no mail")
		return sentMail{}
	}
}

// The client contract of POST /api/me/email, POST /api/me/email/verify, DELETE
// /api/me/email and GET /api/me's email, end to end, then a sign-in with the address.
func TestAddEmailOverHTTP(t *testing.T) {
	mailer := make(chanMailer, 8)
	e, _, err := New(dbtest.Fresh(t, "server_email_tests"), Config{Keys: dbtest.Keys(),
		SignIn:        service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"}, Mailer: mailer},
		MagicLinkBase: "https://duongondro.app/m#",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := serve(t, e, http.MethodPost, devSessionPath, "", nil)
	var session struct{ Token, UserId string }
	_ = json.Unmarshal(rec.Body.Bytes(), &session)
	me := func() map[string]any {
		t.Helper()
		rec := serve(t, e, http.MethodGet, "/api/me", session.Token, nil)
		var out map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("me: %d %s", rec.Code, rec.Body)
		}
		return out
	}
	if _, has := me()["email"]; has {
		t.Fatal("an email before one was added")
	}

	if rec := serve(t, e, http.MethodPost, "/api/me/email", "bogus", map[string]any{"email": "ana@example.com"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodPost, "/api/me/email", session.Token, map[string]any{"email": "nope"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad address: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodPost, "/api/me/email", session.Token, map[string]any{"email": "Ana@Example.com"}); rec.Code != http.StatusNoContent {
		t.Fatalf("request: %d %s", rec.Code, rec.Body)
	}
	mail := mailer.next(t, "confirm", "ana@example.com")
	if !strings.HasPrefix(mail.link, "https://duongondro.app/m/e#") {
		t.Fatalf("link %q", mail.link)
	}
	for _, body := range []map[string]any{{}, {"code": mail.code, "token": "x"}} {
		if rec := serve(t, e, http.MethodPost, "/api/me/email/verify", session.Token, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("verify %v: %d", body, rec.Code)
		}
	}
	if rec := serve(t, e, http.MethodPost, "/api/me/email/verify", session.Token, map[string]any{"code": "ZZZZZZZZ"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodPost, "/api/me/email/verify", "bogus", map[string]any{"code": mail.code}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated verify: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodPost, "/api/me/email/verify", session.Token, map[string]any{"code": mail.code}); rec.Code != http.StatusNoContent {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	if got := me()["email"]; got != "ana@example.com" {
		t.Fatalf("me email %v", got)
	}

	// Replaced by the link of a second address.
	if rec := serve(t, e, http.MethodPost, "/api/me/email", session.Token, map[string]any{"email": "ana2@example.com"}); rec.Code != http.StatusNoContent {
		t.Fatalf("request: %d", rec.Code)
	}
	mail = mailer.next(t, "confirm", "ana2@example.com")
	token := strings.TrimPrefix(mail.link, "https://duongondro.app/m/e#")
	if rec := serve(t, e, http.MethodPost, "/api/auth/magic-links/redeem", "", map[string]any{"token": token}); rec.Code != http.StatusBadRequest {
		t.Fatalf("the confirmation link signed in: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodPost, "/api/me/email/verify", session.Token, map[string]any{"token": token}); rec.Code != http.StatusNoContent {
		t.Fatalf("verify by link: %d %s", rec.Code, rec.Body)
	}
	if got := me()["email"]; got != "ana2@example.com" {
		t.Fatalf("me email %v", got)
	}

	// Another account asking for it: 204 and a mail, then 409.
	rec = serve(t, e, http.MethodPost, devSessionPath, "", nil)
	var other struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &other)
	if rec := serve(t, e, http.MethodPost, "/api/me/email", other.Token, map[string]any{"email": "ana2@example.com"}); rec.Code != http.StatusNoContent {
		t.Fatalf("another account's address: %d", rec.Code)
	}
	mail = mailer.next(t, "confirm", "ana2@example.com")
	if rec := serve(t, e, http.MethodPost, "/api/me/email/verify", other.Token, map[string]any{"code": mail.code}); rec.Code != http.StatusConflict {
		t.Fatalf("verify another account's address: %d %s", rec.Code, rec.Body)
	}

	// Sign in with it by magic link.
	if rec := serve(t, e, http.MethodPost, "/api/auth/magic-links", "", map[string]any{"email": "ana2@example.com"}); rec.Code != http.StatusNoContent {
		t.Fatalf("magic link: %d", rec.Code)
	}
	mail = mailer.next(t, "sign-in", "ana2@example.com")
	rec = serve(t, e, http.MethodPost, "/api/auth/magic-links/redeem", "", map[string]any{"email": "ana2@example.com", "code": mail.code})
	var signedIn struct{ UserId string }
	_ = json.Unmarshal(rec.Body.Bytes(), &signedIn)
	if rec.Code != http.StatusOK || signedIn.UserId != session.UserId {
		t.Fatalf("sign-in by the added address: %d %s", rec.Code, rec.Body)
	}

	// The DEV account has no passkey: the address is its only sign-in.
	if rec := serve(t, e, http.MethodDelete, "/api/me/email", session.Token, nil); rec.Code != http.StatusConflict {
		t.Fatalf("removing the only sign-in: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodDelete, "/api/me/email", other.Token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("removing no address: %d", rec.Code)
	}
}
