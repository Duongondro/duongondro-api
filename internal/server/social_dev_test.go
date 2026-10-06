//go:build DEV

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

type devUser struct {
	token, id string
	identity  ed25519.PrivateKey
}

func newDevUser(t *testing.T, e *echo.Echo) devUser {
	t.Helper()
	rec := serve(t, e, http.MethodPost, devSessionPath, "", nil)
	var s struct{ Token, UserId string }
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if rec := serve(t, e, http.MethodPut, "/api/me/identity", s.Token, map[string]any{"publicKey": []byte(pub)}); rec.Code != http.StatusNoContent {
		t.Fatalf("identity: %d %s", rec.Code, rec.Body)
	}
	return devUser{token: s.Token, id: s.UserId, identity: priv}
}

func statement(u devUser, typ string, v any) map[string]any {
	payload, _ := e2ee.Marshal(v)
	return map[string]any{"payload": payload, "signature": e2ee.SignStatement(u.identity, typ, payload)}
}

// Two people become friends through an invite, one sees the other's streak, and a
// purge takes the purged person off the other's friend list.
func TestFriendsOverHTTP(t *testing.T) {
	e := newTestServer(t, "server_social_tests")
	ana, bo := newDevUser(t, e), newDevUser(t, e)

	expires := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Millisecond).UTC()
	auth := make([]byte, 32)
	_, _ = rand.Read(auth)
	inv := statement(ana, e2ee.TypeInvite, e2ee.Invite{ExpiresAt: expires.UnixMilli(), InviteID: "7K2MQ9XA", Inviter: ana.id, InviterIdentityPk: e2ee.Bytes(ana.identity.Public().(ed25519.PublicKey))})
	body := map[string]any{"id": "7K2MQ9XA", "auth": auth, "expiresAt": expires, "payload": inv["payload"], "signature": inv["signature"], "mac": make([]byte, 32)}
	if rec := serve(t, e, http.MethodPost, "/api/invites", ana.token, body); rec.Code != http.StatusCreated {
		t.Fatalf("create invite: %d %s", rec.Code, rec.Body)
	}
	// The invitee reads it before having any session.
	if rec := serve(t, e, http.MethodGet, "/api/invites/7k2mq9xa", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("get invite: %d %s", rec.Code, rec.Body)
	}
	acc := statement(bo, e2ee.TypeAcceptance, e2ee.Acceptance{InviteID: "7K2MQ9XA", Invitee: bo.id, InviteeIdentityPk: e2ee.Bytes(bo.identity.Public().(ed25519.PublicKey))})
	if rec := serve(t, e, http.MethodPost, "/api/invites/7K2MQ9XA/redemptions", bo.token, map[string]any{"auth": auth, "acceptance": acc}); rec.Code != http.StatusOK {
		t.Fatalf("redeem: %d %s", rec.Code, rec.Body)
	}

	st := e2ee.Streak{Current: 3, Day: today(0), Deadline: time.Now().Add(time.Hour).UnixMilli(), Longest: 3, Practice: "dorje-sempa", Seq: 1, User: ana.id}
	if rec := serve(t, e, http.MethodPut, "/api/streaks/dorje-sempa", ana.token, statement(ana, e2ee.TypeStreak, st)); rec.Code != http.StatusNoContent {
		t.Fatalf("put streak: %d %s", rec.Code, rec.Body)
	}
	rec := serve(t, e, http.MethodGet, "/api/friends/streaks", bo.token, nil)
	var streaks struct {
		Streaks []struct{ UserId, Practice string }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &streaks)
	if len(streaks.Streaks) != 1 || streaks.Streaks[0].UserId != ana.id {
		t.Fatalf("friend's streaks: %s", rec.Body)
	}

	rec = serve(t, e, http.MethodGet, "/api/me/export", ana.token, nil)
	var export map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &export)
	for _, key := range []string{"users", "invites", "friendships", "streaks", "practice_logs"} {
		if _, ok := export[key]; !ok {
			t.Errorf("export lacks %q", key)
		}
	}

	if rec := serve(t, e, http.MethodDelete, "/api/me", ana.token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete me: %d", rec.Code)
	}
	if rec := serve(t, e, http.MethodGet, "/api/me", ana.token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the purged session still works: %d", rec.Code)
	}
	rec = serve(t, e, http.MethodGet, "/api/friends", bo.token, nil)
	var friends struct{ Friends []any }
	_ = json.Unmarshal(rec.Body.Bytes(), &friends)
	if len(friends.Friends) != 0 {
		t.Fatalf("the purged friend is still listed: %s", rec.Body)
	}
}

// today is the UTC civil day offset days from now, for streak statements whose
// deadline the tests take from the clock.
func today(offset int) string {
	return time.Now().UTC().AddDate(0, 0, offset).Format("2006-01-02")
}

// PATCH /api/me: absent fields stay, null clears, a taken username is a 409; the
// display name alone, as the iOS app sends it, still works.
func TestProfileOverHTTP(t *testing.T) {
	e := newTestServer(t, "server_profile_tests")
	ana, bo := newDevUser(t, e), newDevUser(t, e)
	me := func(u devUser) map[string]any {
		t.Helper()
		rec := serve(t, e, http.MethodGet, "/api/me", u.token, nil)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	patch := func(u devUser, body string, want int) {
		t.Helper()
		var v any
		_ = json.Unmarshal([]byte(body), &v)
		if rec := serve(t, e, http.MethodPatch, "/api/me", u.token, v); rec.Code != want {
			t.Fatalf("PATCH %s: %d %s", body, rec.Code, rec.Body)
		}
	}
	patch(ana, `{"displayName": "Ana", "username": "Ana_K", "gender": "female"}`, http.StatusNoContent)
	if m := me(ana); m["displayName"] != "Ana" || m["username"] != "ana_k" || m["gender"] != "female" {
		t.Fatalf("me: %v", m)
	}
	patch(ana, `{"displayName": "Ania"}`, http.StatusNoContent)
	if m := me(ana); m["displayName"] != "Ania" || m["username"] != "ana_k" || m["gender"] != "female" {
		t.Fatalf("a display-name PATCH changed the rest: %v", m)
	}
	patch(bo, `{"username": "ANA_K"}`, http.StatusConflict)
	patch(bo, `{"username": "a"}`, http.StatusBadRequest)
	patch(bo, `{"gender": "robot"}`, http.StatusBadRequest)
	patch(ana, `{"gender": null}`, http.StatusNoContent)
	if m := me(ana); m["username"] != "ana_k" {
		t.Fatalf("clearing the gender touched the username: %v", m)
	} else if _, ok := m["gender"]; ok {
		t.Fatalf("gender not cleared: %v", m)
	}
	patch(ana, `{"username": null}`, http.StatusNoContent)
	if _, ok := me(ana)["username"]; ok {
		t.Fatal("username not cleared")
	}
	if m := me(bo); m["displayName"] != "" {
		t.Fatalf("bo: %v", m)
	}
}
