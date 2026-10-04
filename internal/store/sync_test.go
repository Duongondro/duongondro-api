package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/db/dbtest"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

func newStore(t *testing.T) *store.Store { return store.New(dbtest.New(t)) }

func mkUser(t *testing.T, s *store.Store, name string) string {
	t.Helper()
	id := ids.NewV7().String()
	if err := s.CreateUser(context.Background(), id, name, nil); err != nil {
		t.Fatal(err)
	}
	return id
}

func sealed(b byte) []byte {
	out := make([]byte, 28+256)
	out[0] = b
	return out
}

func TestPracticeLogLastWriteWins(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	u := mkUser(t, s, "Tenzin")
	id := ids.NewV7().String()
	t0 := time.UnixMilli(1_760_000_000_000)

	put := func(b byte, at time.Time, deleted bool) store.PracticeLog {
		t.Helper()
		out, _, err := s.PutPracticeLog(ctx, store.PracticeLog{ID: id, UserID: u, Sealed: sealed(b), KeyVersion: 1, UpdatedAt: at, Deleted: deleted})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := put(1, t0, false); got.Sealed[0] != 1 {
		t.Fatal("first write")
	}
	if got := put(2, t0.Add(time.Millisecond), false); got.Sealed[0] != 2 {
		t.Fatal("newer write wins")
	}
	if got := put(3, t0, false); got.Sealed[0] != 2 || !got.UpdatedAt.Equal(t0.Add(time.Millisecond)) {
		t.Fatal("older write must lose and return the stored row")
	}
	if got := put(4, t0.Add(time.Millisecond), false); got.Sealed[0] != 2 {
		t.Fatal("a tie keeps the stored row")
	}
	if got := put(5, t0.Add(time.Second), true); !got.Deleted || got.Sealed[0] != 5 {
		t.Fatal("soft delete is a newer write")
	}

	// Another user cannot touch the id.
	other := mkUser(t, s, "Dolma")
	_, _, err := s.PutPracticeLog(ctx, store.PracticeLog{ID: id, UserID: other, Sealed: sealed(9), KeyVersion: 1, UpdatedAt: t0.Add(time.Hour)})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign id: %v", err)
	}

	// Old key version.
	if _, err := s.SetKeyVersion(ctx, u, 2); err != nil {
		t.Fatal(err)
	}
	_, cur, err := s.PutPracticeLog(ctx, store.PracticeLog{ID: ids.NewV7().String(), UserID: u, Sealed: sealed(1), KeyVersion: 1, UpdatedAt: t0})
	if !errors.Is(err, store.ErrKeyVersion) || cur != 2 {
		t.Fatalf("old key version: %v %d", err, cur)
	}
}

func TestSyncCursor(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	u := mkUser(t, s, "Tenzin")
	other := mkUser(t, s, "Dolma")
	t0 := time.UnixMilli(1_760_000_000_000)
	write := func(user string, id string, b byte, at time.Time) {
		t.Helper()
		if _, _, err := s.PutPracticeLog(ctx, store.PracticeLog{ID: id, UserID: user, Sealed: sealed(b), KeyVersion: 1, UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	a, b := ids.NewV7().String(), ids.NewV7().String()
	write(u, a, 1, t0)
	write(other, ids.NewV7().String(), 1, t0)

	first, err := s.Sync(ctx, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Full || len(first.Logs) != 1 || first.Logs[0].ID != a || first.KeyVersion != 1 {
		t.Fatalf("first sync %+v", first)
	}

	write(u, b, 1, t0)
	write(u, a, 2, t0.Add(time.Second))
	next, err := s.Sync(ctx, u, &first.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if next.Full || len(next.Logs) != 2 {
		t.Fatalf("incremental sync %+v", next)
	}
	seen := map[string]byte{}
	for _, l := range next.Logs {
		seen[l.ID] = l.Sealed[0]
	}
	if seen[a] != 2 || seen[b] != 1 {
		t.Fatalf("rows %v", seen)
	}

	// Nothing new: an empty page (or repeats), never an error.
	again, err := s.Sync(ctx, u, &next.Cursor)
	if err != nil || again.Full {
		t.Fatalf("idle sync %+v %v", again, err)
	}

	// A foreign generation or a cursor ahead of the counter: full resync.
	foreign := store.Cursor{Generation: ids.NewV7().String(), XID: next.Cursor.XID}
	if r, _ := s.Sync(ctx, u, &foreign); !r.Full || len(r.Logs) != 2 {
		t.Fatalf("foreign generation %+v", r)
	}
	ahead := store.Cursor{Generation: next.Cursor.Generation, XID: next.Cursor.XID + 1_000_000}
	if r, _ := s.Sync(ctx, u, &ahead); !r.Full || len(r.Logs) != 2 {
		t.Fatalf("cursor ahead %+v", r)
	}
}

// A write whose transaction started before a sync and commits after it has
// an xid below that sync's snapshot, but at or above its xmin, so the next
// sync returns it. A timestamp or sequence cursor would lose it for good.
func TestSyncSeesLateCommit(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	u := mkUser(t, s, "Tenzin")

	late, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = late.Rollback(ctx) }()
	lateID := ids.NewV7().String()
	if _, err := late.Exec(ctx, `INSERT INTO practice_logs (id, user_id, sealed, key_version, client_updated_at)
		VALUES ($1, $2, $3, 1, now())`, lateID, u, sealed(7)); err != nil {
		t.Fatal(err)
	}

	// Committed after the late transaction started.
	early := ids.NewV7().String()
	if _, _, err := s.PutPracticeLog(ctx, store.PracticeLog{ID: early, UserID: u, Sealed: sealed(1), KeyVersion: 1, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	during, err := s.Sync(ctx, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(during.Logs) != 1 || during.Logs[0].ID != early {
		t.Fatalf("sync during the late transaction %+v", during)
	}

	if err := late.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := s.Sync(ctx, u, &during.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range after.Logs {
		found = found || l.ID == lateID
	}
	if !found || after.Full {
		t.Fatalf("late commit missed: %+v", after)
	}
}

func TestParseCursor(t *testing.T) {
	c, err := store.ParseCursor("0190F3A1-7B2C-7D4E-8F00-123456789ABC:42")
	if err != nil || c.XID != 42 || c.String() != "0190f3a1-7b2c-7d4e-8f00-123456789abc:42" {
		t.Fatalf("%v %v", c, err)
	}
	for _, bad := range []string{"", "42", "x:42", "0190f3a1-7b2c-7d4e-8f00-123456789abc:", "0190f3a1-7b2c-7d4e-8f00-123456789abc:-1", "0190f3a1-7b2c-7d4e-8f00-123456789abc:1:2"} {
		if _, err := store.ParseCursor(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
