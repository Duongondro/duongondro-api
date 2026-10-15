package service

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/atrest"
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
	unsigned := func(d atrest.Device, authType string) WrapInput {
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
	a := auth.New(f.pool, f.keys)
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

func TestSigningOutOthersDropsTheirPushTokens(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	a := auth.New(f.pool, f.keys)
	n := NewNudges(f.pool, f.keys, nil)
	u, other := f.user(), f.user()
	here, _ := f.device(u, "hardware")
	lost, _ := f.device(u, "hardware")
	theirs, _ := f.device(other, "hardware")
	onHere, _ := a.NewSession(ctx, u.ID)
	onLost, _ := a.NewSession(ctx, u.ID)
	if err := a.BindDevice(ctx, onHere, here.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.BindDevice(ctx, onLost, lost.ID); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		user, device uuid.UUID
		token        string
	}{
		{u.ID, here.ID, "here-token"}, {u.ID, lost.ID, "lost-token"}, {other.ID, theirs.ID, "their-token"},
	} {
		if err := n.PutToken(ctx, d.user, d.device, "fcm", d.token); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.RevokeOthers(ctx, u.ID, onHere); err != nil {
		t.Fatal(err)
	}
	tokens := func(user uuid.UUID) map[uuid.UUID]bool {
		rows, err := db.New(f.pool).PushTokensOf(ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		m := map[uuid.UUID]bool{}
		for _, r := range rows {
			m[r.DeviceID] = true
		}
		return m
	}
	mine := tokens(u.ID)
	if mine[lost.ID] {
		t.Fatal("the phone signed out by sign out everywhere else still has its push token")
	}
	if !mine[here.ID] {
		t.Fatal("this phone's own push token was dropped")
	}
	if !tokens(other.ID)[theirs.ID] {
		t.Fatal("another account's push token was dropped")
	}

	// From a session bound to no device, every one of the account's tokens goes:
	// which phone it is on is unknown, and that app sends its token again.
	if err := n.PutToken(ctx, u.ID, lost.ID, "fcm", "lost-token"); err != nil {
		t.Fatal(err)
	}
	unbound, _ := a.NewSession(ctx, u.ID)
	if _, err := a.RevokeOthers(ctx, u.ID, unbound); err != nil {
		t.Fatal(err)
	}
	if left := tokens(u.ID); len(left) != 0 {
		t.Fatalf("an unbound session's sign out everywhere else left %d tokens", len(left))
	}
}

func TestPushTokenReachesOneDevice(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	n := NewNudges(f.pool, f.keys, nil)
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
	s := NewSocial(f.pool, f.keys)
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
	g := NewGDPR(f.pool, f.keys)
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

// A phone signed out by "sign out everywhere else" or by removing the passkey it signed
// in with stops receiving nudges, as one that signs out itself does; this one keeps them.
func TestSignedOutPhonesStopNudges(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	a := auth.New(f.pool, f.keys)
	s, _ := f.signIn(nil, nil, nil)
	n := NewNudges(f.pool, f.keys, nil)
	u, other := f.user(), f.user()
	tokens := func() int {
		rows, err := f.q.PushTokensOf(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	// Each phone has its own token and a session bound to it.
	signIn := func(credential []byte) (string, string) {
		phone, _ := f.device(u, "hardware")
		var token string
		var err error
		if credential != nil {
			token, err = a.NewPasskeySession(ctx, u.ID, credential)
		} else {
			token, err = a.NewSession(ctx, u.ID)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := a.BindDevice(ctx, token, phone.ID); err != nil {
			t.Fatal(err)
		}
		push := hex.EncodeToString(random(32))
		if err := n.PutToken(ctx, u.ID, phone.ID, "apns", push); err != nil {
			t.Fatal(err)
		}
		return token, push
	}
	passkey := func(userID [16]byte) []byte {
		id := random(16)
		if err := f.q.CreateCredential(ctx, db.CreateCredentialParams{ID: id, UserID: userID,
			DataEncrypted: f.keys.Seal(atrest.CredentialsData, atrest.RowOf(id), []byte(`{}`))}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first, second := passkey(u.ID), passkey(u.ID)
	signIn(first)
	here, _ := signIn(second)
	signIn(nil)
	if tokens() != 3 {
		t.Fatalf("tokens: %d", tokens())
	}
	if err := s.RemovePasskey(ctx, u.ID, first); err != nil {
		t.Fatal(err)
	}
	if tokens() != 2 {
		t.Fatalf("the removed passkey's phone keeps its token: %d left", tokens())
	}
	// Someone else's passkey id removes nothing of this account's.
	if err := s.RemovePasskey(ctx, other.ID, second); !errors.Is(err, ErrNotFound) || tokens() != 2 {
		t.Fatalf("another account's removal: %v, %d left", err, tokens())
	}
	if _, err := a.RevokeOthers(ctx, u.ID, here); err != nil {
		t.Fatal(err)
	}
	if tokens() != 1 {
		t.Fatalf("after signing out everywhere else: %d left, want this phone's", tokens())
	}
}
