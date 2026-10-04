package server

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
)

type syncJSON struct {
	Cursor     string            `json:"cursor"`
	Full       bool              `json:"full"`
	KeyVersion int32             `json:"keyVersion"`
	Logs       []practiceLogJSON `json:"logs"`
}

func logBody(b byte, updatedAt int64, keyVersion int32, deleted bool) map[string]any {
	sealed := make([]byte, 28+256*2)
	sealed[0] = b
	return map[string]any{"sealed": e2ee.Bytes(sealed), "keyVersion": keyVersion, "updatedAt": updatedAt, "deleted": deleted}
}

func TestPracticeLogsAndSync(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	id := ids.NewV7().String()
	now := e.clock().UnixMilli()

	r := e.call("PUT", "/api/practice-logs/"+id, u.Token, logBody(1, now, 1, false))
	e.want(r, http.StatusOK, "")
	var got practiceLogJSON
	r.json(t, &got)
	if got.ID != id || got.UpdatedAt != now || got.Sealed[0] != 1 || got.Deleted {
		t.Fatalf("stored %s", r.Body)
	}
	// An older write gets the stored row back.
	r = e.call("PUT", "/api/practice-logs/"+id, u.Token, logBody(2, now-1, 1, false))
	e.want(r, http.StatusOK, "")
	got = practiceLogJSON{}
	r.json(t, &got)
	if got.Sealed[0] != 1 {
		t.Fatalf("older write won: %s", r.Body)
	}

	var first syncJSON
	r = e.call("GET", "/api/sync", u.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &first)
	if !first.Full || len(first.Logs) != 1 || first.KeyVersion != 1 || first.Cursor == "" {
		t.Fatalf("first sync %s", r.Body)
	}

	// Soft delete, then an incremental sync shows the tombstone.
	e.want(e.call("PUT", "/api/practice-logs/"+id, u.Token, logBody(3, now+1, 1, true)), http.StatusOK, "")
	var next syncJSON
	r = e.call("GET", "/api/sync?since="+url.QueryEscape(first.Cursor), u.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &next)
	if next.Full || len(next.Logs) != 1 || !next.Logs[0].Deleted {
		t.Fatalf("incremental sync %s", r.Body)
	}

	// Another user sees nothing and cannot write the id.
	other := e.newUser("Dolma")
	r = e.call("GET", "/api/sync", other.Token, nil)
	var empty syncJSON
	r.json(t, &empty)
	if len(empty.Logs) != 0 {
		t.Fatalf("leak %s", r.Body)
	}
	e.want(e.call("PUT", "/api/practice-logs/"+id, other.Token, logBody(4, now+5, 1, false)), http.StatusNotFound, "not_found")

	// Key rotation: an old key version is refused with the current one.
	e.want(e.call("PUT", "/api/me/key-version", u.Token, map[string]any{"keyVersion": 2}), http.StatusOK, "")
	r = e.call("PUT", "/api/practice-logs/"+ids.NewV7().String(), u.Token, logBody(5, now, 1, false))
	e.want(r, http.StatusUnprocessableEntity, "old_key_version")
	var kv keyVersionError
	r.json(t, &kv)
	if kv.CurrentKeyVersion != 2 {
		t.Fatalf("current %d", kv.CurrentKeyVersion)
	}
}

func TestPracticeLogValidation(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	now := e.clock()
	ok := ids.NewV7().String()
	e.want(e.call("PUT", "/api/practice-logs/"+ok, u.Token, logBody(1, now.Add(23*time.Hour).UnixMilli(), 1, false)), http.StatusOK, "")

	future := logBody(1, now.Add(25*time.Hour).UnixMilli(), 1, false)
	e.want(e.call("PUT", "/api/practice-logs/"+ids.NewV7().String(), u.Token, future), http.StatusBadRequest, "bad_request")
	e.want(e.call("PUT", "/api/practice-logs/6f1c2a9e-3b4d-4e5f-9a0b-1c2d3e4f5a6b", u.Token, logBody(1, now.UnixMilli(), 1, false)), http.StatusBadRequest, "bad_request") // v4
	for _, size := range []int{0, 28, 28 + 255, 28 + 256 + 1, 28 + 256*64} {
		body := map[string]any{"sealed": e2ee.Bytes(make([]byte, size)), "keyVersion": 1, "updatedAt": now.UnixMilli(), "deleted": false}
		e.want(e.call("PUT", "/api/practice-logs/"+ids.NewV7().String(), u.Token, body), http.StatusBadRequest, "bad_request")
	}
	e.want(e.call("PUT", "/api/practice-logs/"+ids.NewV7().String(), u.Token, logBody(1, now.UnixMilli(), 0, false)), http.StatusBadRequest, "bad_request")

	for _, bad := range []string{"x", "42", "nope:1", "0190f3a1-7b2c-7d4e-8f00-123456789abc:x"} {
		e.want(e.call("GET", "/api/sync?since="+url.QueryEscape(bad), u.Token, nil), http.StatusBadRequest, "bad_request")
	}
	// A cursor of another generation means a full resync.
	r := e.call("GET", "/api/sync?since="+url.QueryEscape(ids.NewV7().String()+":5"), u.Token, nil)
	e.want(r, http.StatusOK, "")
	var s syncJSON
	r.json(t, &s)
	if !s.Full || len(s.Logs) != 1 {
		t.Fatalf("foreign generation %s", r.Body)
	}
	e.want(e.call("GET", "/api/sync", "", nil), http.StatusUnauthorized, "unauthorized")
}
