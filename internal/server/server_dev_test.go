//go:build DEV

package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/dbtest"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func newTestServer(t *testing.T, schema string) *echo.Echo {
	t.Helper()
	e, _, err := New(dbtest.Fresh(t, schema), Config{
		SignIn:        service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"}},
		MagicLinkBase: "https://duongondro.app/m#",
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func serve(t *testing.T, e *echo.Echo, method, target, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, target, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// A device's first steps against the API, through the DEV sign-in: register,
// upload a sealed log, sync it back, sign out.
func TestFirstSync(t *testing.T) {
	e := newTestServer(t, "server_tests")

	rec := serve(t, e, http.MethodPost, devSessionPath, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("dev session: %d %s", rec.Code, rec.Body)
	}
	var session struct{ Token, UserId string }
	_ = json.Unmarshal(rec.Body.Bytes(), &session)

	if rec := serve(t, e, http.MethodGet, "/api/me", "bogus", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bogus token: %d", rec.Code)
	}

	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	rec = serve(t, e, http.MethodPost, "/api/devices", session.Token, map[string]any{"publicKey": key.PublicKey().Bytes(), "tier": "software"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register device: %d %s", rec.Code, rec.Body)
	}

	sealed := make([]byte, 284)
	_, _ = rand.Read(sealed)
	id := uuid.NewV7()
	rec = serve(t, e, http.MethodPut, "/api/practice-logs/"+id.String(), session.Token,
		map[string]any{"sealed": sealed, "keyVersion": 1, "updatedAt": time.Now().UTC()})
	if rec.Code != http.StatusOK {
		t.Fatalf("put log: %d %s", rec.Code, rec.Body)
	}
	rec = serve(t, e, http.MethodPut, "/api/practice-logs/"+id.String(), session.Token,
		map[string]any{"sealed": sealed, "keyVersion": 7, "updatedAt": time.Now().UTC()})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("future key version: %d", rec.Code)
	}

	rec = serve(t, e, http.MethodGet, "/api/sync", session.Token, nil)
	var sync struct {
		Cursor string
		Full   bool
		Logs   []struct{ Id string }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sync)
	if rec.Code != http.StatusOK || !sync.Full || len(sync.Logs) != 1 || sync.Logs[0].Id != id.String() {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}

	// The same user again, by id, as a second simulator would.
	if rec := serve(t, e, http.MethodPost, devSessionPath+"?user="+session.UserId, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("dev session for an existing user: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodDelete, "/api/me/session", session.Token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("sign out: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodGet, "/api/me", session.Token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after sign out: %d", rec.Code)
	}
}

// The association files the apex serves for Universal Links, App Links and passkeys.
func TestWellKnown(t *testing.T) {
	e, _, err := New(dbtest.Fresh(t, "server_wellknown_tests"), Config{
		SignIn:    service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"}},
		WellKnown: WellKnown{AppleAppIDs: []string{"TEAM.app.duongondro.ios"}, AndroidPackage: "app.duongondro", AndroidFingerprints: []string{"AB:CD"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/.well-known/apple-app-site-association", "/.well-known/assetlinks.json"} {
		rec := serve(t, e, http.MethodGet, path, "", nil)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	rec := serve(t, e, http.MethodPost, "/api/client-errors", "bogus", map[string]any{"kind": "error", "message": "x"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("client error without a session: %d", rec.Code)
	}
}

// The apex serves the website and the association files and nothing of the API;
// www redirects to the apex; the API host never serves the website.
func TestWebsiteHosts(t *testing.T) {
	e, _, err := New(dbtest.Fresh(t, "server_website_tests"), Config{
		SignIn:    service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"}},
		WellKnown: WellKnown{AppleAppIDs: []string{"TEAM.app.duongondro.ios"}},
		WebHosts:  []string{"duongondro.app", "www.duongondro.app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("duongondro.app", "/I/7K2MQ9XA"); rec.Code != http.StatusOK || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("invite page on the apex: %d", rec.Code)
	}
	if rec := get("duongondro.app", "/.well-known/apple-app-site-association"); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`{"/":"/m"}`)) {
		t.Fatalf("association file on the apex: %d %s", rec.Code, rec.Body)
	}
	if rec := get("duongondro.app", "/api/version"); rec.Code != http.StatusNotFound {
		t.Fatalf("API on the apex: %d", rec.Code)
	}
	if rec := get("www.duongondro.app:443", "/privacy/?x=1"); rec.Code != http.StatusMovedPermanently ||
		rec.Header().Get("Location") != "https://duongondro.app/privacy/?x=1" {
		t.Fatalf("www: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("api.duongondro.app", "/api/version"); rec.Code != http.StatusOK {
		t.Fatalf("API host: %d", rec.Code)
	}
	if rec := get("api.duongondro.app", "/privacy/"); rec.Code != http.StatusNotFound {
		t.Fatalf("website on the API host: %d", rec.Code)
	}
}

// A sign-up carries an invitation or an admission code; an unknown code is a 404,
// like an unknown invitation, and neither is a 400.
func TestSignUpProofOverHTTP(t *testing.T) {
	e := newTestServer(t, "server_signup_tests")
	if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", map[string]any{"admissionCode": "zzzz-zzzz-zzzz-zzzz"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown admission code: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("no proof: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, e, http.MethodPost, "/api/auth/passkeys/sign-up", "", map[string]any{"invite": map[string]any{"id": "7K2MQ9XA", "auth": make([]byte, 32)}}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown invitation: %d %s", rec.Code, rec.Body)
	}
}

// A magic link is redeemed with its token alone, or with the address and the code.
func TestMagicLinkRedemptionShapes(t *testing.T) {
	e := newTestServer(t, "server_magic_tests")
	for name, body := range map[string]map[string]any{
		"nothing":        {},
		"code alone":     {"code": "7K2M Q9XA"},
		"token and code": {"token": "x", "email": "bo@example.com", "code": "7K2M Q9XA"},
		"unknown token":  {"token": "x"},
		"no such link":   {"email": "bo@example.com", "code": "7k2m-q9xa"},
		"malformed code": {"email": "bo@example.com", "code": "7K2M"},
	} {
		if rec := serve(t, e, http.MethodPost, "/api/auth/magic-links/redeem", "", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}
