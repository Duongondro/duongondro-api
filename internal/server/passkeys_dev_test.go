//go:build DEV

package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/dbtest"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// Settings › Passkeys over HTTP: ids in base64url, another account's passkey looks
// missing, a nameless rename is refused, and removing this session's passkey signs
// it out.
func TestPasskeysOverHTTP(t *testing.T) {
	pool := dbtest.Fresh(t, "server_passkeys")
	keys := dbtest.Keys()
	e, _, err := New(pool, Config{Keys: keys,
		SignIn: service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	q, a := db.New(pool), auth.New(pool, keys)
	ana, bo := newDevUser(t, e), newDevUser(t, e)
	passkey := func(u devUser) []byte {
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		if err := q.CreateCredential(ctx, db.CreateCredentialParams{ID: id, UserID: uuid.MustParse(u.id),
			DataEncrypted: keys.Seal(atrest.CredentialsData, atrest.RowOf(id), []byte(`{}`))}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	path := func(id []byte) string { return "/api/me/credentials/" + base64.RawURLEncoding.EncodeToString(id) }
	first, second, bos := passkey(ana), passkey(ana), passkey(bo)
	viaFirst, err := a.NewPasskeySession(ctx, uuid.MustParse(ana.id), first)
	if err != nil {
		t.Fatal(err)
	}

	if rec := serve(t, e, http.MethodGet, "/api/me/credentials", "not-a-session", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("list with an unknown token: %d", rec.Code)
	}
	rec := serve(t, e, http.MethodGet, "/api/me/credentials", viaFirst, nil)
	var list struct {
		Passkeys []struct {
			ID      string
			Name    *string
			Current bool
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if len(list.Passkeys) != 2 || list.Passkeys[0].ID != base64.RawURLEncoding.EncodeToString(first) || !list.Passkeys[0].Current || list.Passkeys[1].Current {
		t.Fatalf("list: %s", rec.Body)
	}

	for _, target := range []string{path(bos), "/api/me/credentials/not%20base64", path([]byte("missing"))} {
		if rec := serve(t, e, http.MethodPatch, target, ana.token, map[string]any{"name": "x"}); rec.Code != http.StatusNotFound {
			t.Fatalf("rename %s: %d %s", target, rec.Code, rec.Body)
		}
		if rec := serve(t, e, http.MethodDelete, target, ana.token, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("delete %s: %d %s", target, rec.Code, rec.Body)
		}
	}
	if rec := serve(t, e, http.MethodPatch, path(second), ana.token, map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a rename without a name: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, e, http.MethodPatch, path(second), ana.token, map[string]any{"name": "Laptop"}); rec.Code != http.StatusNoContent {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, e, http.MethodPatch, path(second), ana.token, map[string]any{"name": nil}); rec.Code != http.StatusNoContent {
		t.Fatalf("clearing the name: %d %s", rec.Code, rec.Body)
	}

	if rec := serve(t, e, http.MethodDelete, path(first), viaFirst, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("removing this session's passkey: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, e, http.MethodGet, "/api/me/credentials", viaFirst, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the session lives on after its passkey: %d", rec.Code)
	}
	// The DEV session has no e-mail: its last passkey stays.
	if rec := serve(t, e, http.MethodDelete, path(second), ana.token, nil); rec.Code != http.StatusConflict {
		t.Fatalf("removing the last way to sign in: %d %s", rec.Code, rec.Body)
	}
}
