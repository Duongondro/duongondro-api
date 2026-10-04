package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMagicLinkSignIn(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	if err := e.store.AddEmailIdentity(context.Background(), u.ID, "tenzin@example.org"); err != nil {
		t.Fatal(err)
	}

	e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": " Tenzin@Example.org "}), http.StatusAccepted, "")
	link := e.mail.last("tenzin@example.org")
	tok, ok := strings.CutPrefix(link, "https://duongondro.app/m#")
	if !ok || len(tok) != 43 {
		t.Fatalf("link %q", link)
	}

	r := e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": tok})
	e.want(r, http.StatusOK, "")
	var res struct {
		Status  string `json:"status"`
		Session struct {
			Token  string `json:"token"`
			UserID string `json:"userId"`
		} `json:"session"`
	}
	r.json(t, &res)
	if res.Status != "signed_in" || res.Session.UserID != u.ID {
		t.Fatalf("result %s", r.Body)
	}

	// Single use.
	e.want(e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": tok}), http.StatusUnauthorized, "invalid_token")

	// The new session works, and signs out.
	var me accountJSON
	r = e.call("GET", "/api/me", res.Session.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &me)
	if me.ID != u.ID || me.DisplayName != "Tenzin" || me.KeyVersion != 1 || len(me.IdentityPK) != 32 {
		t.Fatalf("me %s", r.Body)
	}
	e.want(e.call("DELETE", "/api/me/session", res.Session.Token, nil), http.StatusNoContent, "")
	e.want(e.call("GET", "/api/me", res.Session.Token, nil), http.StatusUnauthorized, "unauthorized")
}

func TestMagicLinkUnknownAddressNeedsInvite(t *testing.T) {
	e := newEnv(t)
	// Same answer as for a member: no enumeration.
	e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": "new@example.org"}), http.StatusAccepted, "")
	tok := strings.TrimPrefix(e.mail.last("new@example.org"), "https://duongondro.app/m#")
	r := e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": tok})
	e.want(r, http.StatusOK, "")
	var res struct {
		Status      string `json:"status"`
		SignupToken string `json:"signupToken"`
		Session     any    `json:"session"`
	}
	r.json(t, &res)
	if res.Status != "signup_required" || len(res.SignupToken) != 43 || res.Session != nil {
		t.Fatalf("result %s", r.Body)
	}
}

func TestMagicLinkExpires(t *testing.T) {
	e := newEnv(t)
	e.advance(-20 * time.Minute) // the link is issued 20 minutes ago
	e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": "late@example.org"}), http.StatusAccepted, "")
	tok := strings.TrimPrefix(e.mail.last("late@example.org"), "https://duongondro.app/m#")
	e.want(e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": tok}), http.StatusUnauthorized, "invalid_token")
}

func TestMagicLinkValidationAndLimits(t *testing.T) {
	e := newEnv(t)
	for _, bad := range []string{`{"email":"nobody"}`, `{"email":"A <a@example.org>"}`, `{"email":"a@localhost"}`, `{"email":"a@example.org","x":1}`, `[]`, `{"email":"a@example.org"}{}`} {
		e.want(e.call("POST", "/api/auth/magic-link", "", bad), http.StatusBadRequest, "bad_request")
	}
	e.want(e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": "nope"}), http.StatusUnauthorized, "invalid_token")
	e.want(e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": ""}), http.StatusBadRequest, "bad_request")

	// Five mails an hour per address.
	for i := 0; i < 5; i++ {
		e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": "busy@example.org"}), http.StatusAccepted, "")
	}
	e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": "busy@example.org"}), http.StatusTooManyRequests, "rate_limited")
	e.advance(13 * time.Minute) // one token back
	e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": "busy@example.org"}), http.StatusAccepted, "")
}

func TestBodyCap(t *testing.T) {
	e := newEnv(t)
	big := `{"email":"` + strings.Repeat("a", MaxBodyBytes) + `@example.org"}`
	e.want(e.call("POST", "/api/auth/magic-link", "", big), http.StatusRequestEntityTooLarge, "too_large")
}

func TestUpdateMe(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	r := e.call("PATCH", "/api/me", u.Token, map[string]any{"displayName": "Tenzin D.", "avatarRef": "avatars/abc"})
	e.want(r, http.StatusOK, "")
	var me accountJSON
	r.json(t, &me)
	if me.DisplayName != "Tenzin D." || me.AvatarRef == nil || *me.AvatarRef != "avatars/abc" {
		t.Fatalf("me %s", r.Body)
	}
	// Absent keys stay, null clears the avatar.
	r = e.call("PATCH", "/api/me", u.Token, map[string]any{"avatarRef": nil})
	e.want(r, http.StatusOK, "")
	me = accountJSON{}
	r.json(t, &me)
	if me.DisplayName != "Tenzin D." || me.AvatarRef != nil {
		t.Fatalf("me %s", r.Body)
	}
	for _, bad := range []any{
		map[string]any{"displayName": ""},
		map[string]any{"displayName": nil},
		map[string]any{"displayName": " padded"},
		map[string]any{"displayName": strings.Repeat("x", 65)},
		map[string]any{"displayName": "tab\there"},
		map[string]any{"keyVersion": 3},
	} {
		e.want(e.call("PATCH", "/api/me", u.Token, bad), http.StatusBadRequest, "bad_request")
	}
	e.want(e.call("PATCH", "/api/me", "", map[string]any{}), http.StatusUnauthorized, "unauthorized")
	e.want(e.call("GET", "/api/me", "short", nil), http.StatusUnauthorized, "unauthorized")
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:4000", "", "203.0.113.9"},
		{"203.0.113.9:4000", "198.51.100.1", "203.0.113.9"}, // not from the proxy: ignored
		{"127.0.0.1:4000", "10.0.0.1, 198.51.100.1", "198.51.100.1"},
		{"[::1]:4000", "198.51.100.2", "198.51.100.2"},
		{"127.0.0.1:4000", "", "127.0.0.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("%s %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestLimiterRefills(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter(func() time.Time { return now }, 2, time.Minute)
	if !l.allow("k") || !l.allow("k") || l.allow("k") {
		t.Fatal("burst of 2")
	}
	if !l.allow("other") {
		t.Fatal("keys are independent")
	}
	now = now.Add(30 * time.Second)
	if !l.allow("k") || l.allow("k") {
		t.Fatal("one token after half the period")
	}
}
