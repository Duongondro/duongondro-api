//go:build DEV

package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
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
	"github.com/Duongondro/duongondro-api/internal/e2ee"
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

// A passkey that unlocks the counts, over HTTP: publish U, wrap to it, seal it to a
// passkey, and read it all back as a new phone would.
func TestPasskeyUnlockOverHTTP(t *testing.T) {
	pool := dbtest.Fresh(t, "server_unlock")
	keys := dbtest.Keys()
	e, _, err := New(pool, Config{Keys: keys,
		SignIn: service.SignInConfig{RPID: "duongondro.app", RPOrigins: []string{"https://duongondro.app"}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	ana := newDevUser(t, e)
	user := e2ee.UUID(uuid.MustParse(ana.id))
	cred := make([]byte, 16)
	_, _ = rand.Read(cred)
	if err := db.New(pool).CreateCredential(ctx, db.CreateCredentialParams{ID: cred, UserID: uuid.MustParse(ana.id),
		DataEncrypted: keys.Seal(atrest.CredentialsData, atrest.RowOf(cred), []byte(`{}`))}); err != nil {
		t.Fatal(err)
	}
	unlockPath := "/api/me/credentials/" + base64.RawURLEncoding.EncodeToString(cred) + "/unlock"

	if rec := serve(t, e, http.MethodGet, "/api/me/user-key", ana.token, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no user key yet: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodGet, unlockPath, ana.token, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no box yet: %d", rec.Code)
	}

	u, _ := ecdh.P256().GenerateKey(rand.Reader)
	ukID := uuid.NewV7()
	if rec := serve(t, e, http.MethodPut, "/api/me/user-key", ana.token, statement(ana, e2ee.TypeUserKey,
		e2ee.UserKey{ID: ukID.String(), PK: u.PublicKey().Bytes(), User: ana.id, Version: 1})); rec.Code != http.StatusNoContent {
		t.Fatalf("user key: %d %s", rec.Code, rec.Body)
	}
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	aad := e2ee.WrapAAD(user, 1, e2ee.UUID(ukID), e2ee.KindPracticeKey)
	nonce := make([]byte, e2ee.NonceSize)
	epk, wbox, _ := e2ee.Wrap(u.PublicKey(), eph, make([]byte, 32), aad, nonce)
	if rec := serve(t, e, http.MethodPost, "/api/me/user-key/wraps", ana.token, map[string]any{"userKeyId": ukID, "kind": 1, "keyVersion": 1,
		"ephemeralKey": epk, "box": wbox, "signature": e2ee.SignWrap(ana.identity, epk, wbox, aad, u.PublicKey().Bytes())}); rec.Code != http.StatusNoContent {
		t.Fatalf("wrap to U: %d %s", rec.Code, rec.Body)
	}
	boxAAD := e2ee.PasskeyBoxAAD(user, e2ee.UUID(ukID), cred)
	box, _ := e2ee.SealPasskeyBox(e2ee.PRFKey(make([]byte, 32), user), boxAAD, u.Bytes(), nonce)
	if rec := serve(t, e, http.MethodPut, unlockPath, ana.token, map[string]any{"userKeyId": ukID, "box": box,
		"signature": e2ee.SignPasskeyBox(ana.identity, boxAAD, box)}); rec.Code != http.StatusNoContent {
		t.Fatalf("passkey box: %d %s", rec.Code, rec.Body)
	}

	rec := serve(t, e, http.MethodGet, unlockPath, ana.token, nil)
	var got struct {
		Box     []byte
		UserKey struct {
			Id        uuid.UUID
			Statement struct{ Payload, Signature []byte }
			Wraps     []struct{ Kind int }
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("unlock: %d %s", rec.Code, rec.Body)
	}
	if string(got.Box) != string(box) || got.UserKey.Id != ukID || len(got.UserKey.Wraps) != 1 ||
		!e2ee.VerifyStatement(ana.identity.Public().(ed25519.PublicKey), e2ee.TypeUserKey, got.UserKey.Statement.Payload, got.UserKey.Statement.Signature) {
		t.Fatalf("unlock: %s", rec.Body)
	}
	rec = serve(t, e, http.MethodGet, "/api/me/credentials", ana.token, nil)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"canUnlock":true`)) {
		t.Fatalf("the passkey list does not say it unlocks: %s", rec.Body)
	}
	if rec := serve(t, e, http.MethodDelete, unlockPath, ana.token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("removing the box: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodGet, unlockPath, ana.token, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("the box outlived its removal: %d", rec.Code)
	}
}
