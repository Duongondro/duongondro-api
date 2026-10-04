package service

import (
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

// What a session alone (no identity key) may do to wraps: nothing it could use to
// break the user's keys.
func TestWrapsASessionCannotBreak(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	u := f.user()
	phone, _ := f.device(u, "hardware")
	u, identity := f.withIdentity(u)
	if err := f.wraps.Put(ctx, u, phone.ID, signedWrap(u, identity, phone, e2ee.KindPracticeKey, 1)); err != nil {
		t.Fatal(err)
	}
	unsigned := func(d db.Device, authType string) WrapInput {
		w := signedWrap(u, identity, d, e2ee.KindPracticeKey, 1)
		w.AuthType, w.Authenticator = authType, random(32)
		return w
	}
	// A signed wrap is never replaced by an unverifiable one.
	if err := f.wraps.Put(ctx, u, phone.ID, unsigned(phone, "self")); !isConflict(err) {
		t.Fatalf("self tag over a signed wrap: %v", err)
	}
	// An enrolment tag only for a device without wraps.
	if err := f.wraps.Put(ctx, u, phone.ID, unsigned(phone, "enrol")); !isConflict(err) {
		t.Fatalf("enrolment tag for a device with wraps: %v", err)
	}
	// A device a session registered and enrolled itself, outside the signed list,
	// holds the key but does not block the user's rotation.
	planted, _ := f.device(u, "software")
	if err := f.wraps.Put(ctx, u, planted.ID, unsigned(planted, "enrol")); err != nil {
		t.Fatal(err)
	}
	list := e2ee.DeviceList{Devices: []e2ee.Device{{ID: phone.ID.String(), PK: phone.PublicKey, Tier: "hardware"}}, IssuedAt: 1, User: u.ID.String(), Version: 1}
	payload, _ := e2ee.Marshal(list)
	if err := f.devices.PutDeviceList(ctx, u, payload, e2ee.SignStatement(identity, e2ee.TypeDeviceList, payload)); err != nil {
		t.Fatal(err)
	}
	rotation := []RotationWrap{{DeviceID: phone.ID, WrapInput: signedWrap(u, identity, phone, e2ee.KindPracticeKey, 2)}}
	forged := []RotationWrap{{DeviceID: phone.ID, WrapInput: signedWrap(u, identity, phone, e2ee.KindPracticeKey, 2)}}
	forged[0].AuthType, forged[0].Authenticator = "self", random(32)
	if err := f.wraps.Rotate(ctx, u, 2, forged); !isValidation(err) {
		t.Fatalf("a rotation with unsigned wraps: %v", err)
	}
	if err := f.wraps.Rotate(ctx, u, 2, rotation); err != nil {
		t.Fatalf("rotation, with a planted holder outside the list: %v", err)
	}
}

func TestSessionsEndWithTheirDevice(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	a := auth.New(f.pool)
	u := f.user()
	phone, _ := f.device(u, "hardware")
	onPhone, _ := a.NewSession(ctx, u.ID)
	elsewhere, _ := a.NewSession(ctx, u.ID)
	if err := a.BindDevice(ctx, onPhone, phone.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.devices.Delete(ctx, u.ID, phone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SessionUser(ctx, onPhone); err != auth.ErrInvalidToken {
		t.Fatalf("the removed phone's session still works: %v", err)
	}
	third, _ := a.NewSession(ctx, u.ID)
	if n, err := a.RevokeOthers(ctx, u.ID, third); err != nil || n != 1 {
		t.Fatalf("sign out everywhere else: %v %d", err, n)
	}
	if _, err := a.SessionUser(ctx, elsewhere); err != auth.ErrInvalidToken {
		t.Fatal("another session survived signing out everywhere else")
	}
	if _, err := a.SessionUser(ctx, third); err != nil {
		t.Fatal("the current session was signed out too")
	}
}

func TestPushTokenReachesOneDevice(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	n := NewNudges(f.pool, nil)
	ana, bo := f.user(), f.user()
	anaPhone, _ := f.device(ana, "hardware")
	boPhone, _ := f.device(bo, "hardware")
	if err := n.PutToken(ctx, ana.ID, anaPhone.ID, "apns", boToken); err != nil {
		t.Fatal(err)
	}
	// The same phone, now signed in to bo's account, registers the same token.
	if err := n.PutToken(ctx, bo.ID, boPhone.ID, "apns", boToken); err != nil {
		t.Fatal(err)
	}
	if tokens, _ := f.q.PushTokensOf(ctx, ana.ID); len(tokens) != 0 {
		t.Fatal("ana's account would still push to a phone now signed in as bo")
	}
}

func TestStreakDeadlineBounds(t *testing.T) {
	f := setup(t)
	s := NewSocial(f.pool)
	ana := f.member()
	for name, deadline := range map[string]time.Time{
		"before the day": time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
		"a week after":   time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC),
		"the year 3000":  time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		st := e2ee.Streak{Current: 1, Day: "2026-10-04", Deadline: deadline.UnixMilli(), Longest: 1, Practice: "mandala", Seq: 1, User: ana.ID.String()}
		payload, sig := sign(ana, e2ee.TypeStreak, st)
		if _, _, err := s.PutStreak(t.Context(), ana.User, "mandala", payload, sig); !isValidation(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPurgesAreReappliedAfterARestore(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	g := NewGDPR(f.pool)
	u := f.user()
	if err := g.Purge(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	// A backup from before the purge comes back.
	if _, err := f.pool.Exec(ctx, `INSERT INTO users (id) VALUES ($1)`, u.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := g.ReapplyPurges(ctx); err != nil || n != 1 {
		t.Fatalf("reapply: %v %d", err, n)
	}
	var left int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, u.ID).Scan(&left)
	if left != 0 {
		t.Fatal("the purged account came back")
	}
}
