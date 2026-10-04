package server

import (
	"net/http"
	"testing"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

func TestExportAndDeleteMe(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	f := e.newUser("Dolma")
	e.befriend(u, f)
	d := newDevice(t)
	e.registerDevice(u, d)
	e.want(e.call("PUT", "/api/practice-logs/"+ids.NewV7().String(), u.Token, logBody(1, e.clock().UnixMilli(), 1, false)), http.StatusOK, "")
	e.want(e.call("PUT", "/api/wraps", u.Token, makeWrap(t, u, u, d, e2ee.KindPracticeKey, 1)), http.StatusNoContent, "")
	if _, err := e.store.Pool().Exec(t.Context(), `INSERT INTO auth_identities (user_id, provider, subject) VALUES ($1, 'apple', 'apple-sub')`, u.ID); err != nil {
		t.Fatal(err)
	}

	r := e.call("GET", "/api/me/export", u.Token, nil)
	e.want(r, http.StatusOK, "")
	var exp struct {
		UserID     string                      `json:"userId"`
		ExportedAt int64                       `json:"exportedAt"`
		Tables     map[string][]map[string]any `json:"tables"`
	}
	r.json(t, &exp)
	if exp.UserID != u.ID || exp.ExportedAt == 0 {
		t.Fatalf("export header %s", r.Body)
	}
	for _, tbl := range store.ExportTables() {
		if _, ok := exp.Tables[tbl]; !ok {
			t.Errorf("export lacks %s", tbl)
		}
	}
	if len(exp.Tables["practice_logs"]) != 1 || len(exp.Tables["devices"]) != 1 || len(exp.Tables["friendships"]) != 1 || len(exp.Tables["wraps"]) != 1 {
		t.Fatalf("export rows %s", r.Body)
	}
	if _, ok := exp.Tables["sessions"][0]["token_hash"]; ok {
		t.Fatal("token hash exported")
	}
	e.want(e.call("GET", "/api/me/export", "", nil), http.StatusUnauthorized, "unauthorized")

	e.want(e.call("DELETE", "/api/me", u.Token, nil), http.StatusNoContent, "")
	if len(e.revoker.revoked) != 1 || e.revoker.revoked[0] != "apple-sub" {
		t.Fatalf("revoked %v", e.revoker.revoked)
	}
	e.want(e.call("GET", "/api/me", u.Token, nil), http.StatusUnauthorized, "unauthorized")
	e.want(e.call("DELETE", "/api/me", u.Token, nil), http.StatusUnauthorized, "unauthorized")
	// The friend's next fetch is the tombstone: the purged user is gone.
	var friends []any
	e.call("GET", "/api/friends", f.Token, nil).json(t, &friends)
	if len(friends) != 0 {
		t.Fatalf("friends after purge %v", friends)
	}
	e.want(e.call("GET", "/api/users/"+u.ID+"/device-list", f.Token, nil), http.StatusNotFound, "not_found")
}
