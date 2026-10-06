package service

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

type member struct {
	db.User
	identity ed25519.PrivateKey
}

func (f *fixture) member() member {
	u, priv := f.withIdentity(f.user())
	return member{User: u, identity: priv}
}

func sign(m member, typ string, v any) (payload, sig []byte) {
	payload, err := e2ee.Marshal(v)
	if err != nil {
		panic(err)
	}
	return payload, e2ee.SignStatement(m.identity, typ, payload)
}

// invite creates an invite by m and returns its id and auth.
func (f *fixture) invite(s *Social, m member, id string) []byte {
	f.t.Helper()
	auth := random(32)
	expires := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Millisecond)
	payload, sig := sign(m, e2ee.TypeInvite, e2ee.Invite{ExpiresAt: expires.UnixMilli(), InviteID: id, Inviter: m.ID.String(), InviterIdentityPk: m.IdentityPublicKey})
	if err := s.CreateInvite(f.t.Context(), m.User, id, auth, expires, payload, sig, random(32)); err != nil {
		f.t.Fatalf("create invite: %v", err)
	}
	return auth
}

func acceptance(m member, id string) ([]byte, []byte) {
	return sign(m, e2ee.TypeAcceptance, e2ee.Acceptance{InviteID: id, Invitee: m.ID.String(), InviteeIdentityPk: m.IdentityPublicKey})
}

func TestInvites(t *testing.T) {
	f := setup(t)
	s := NewSocial(f.pool)
	ctx := t.Context()
	ana, bo, cy := f.member(), f.member(), f.member()

	// A statement must match the invite it travels with.
	expires := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	payload, sig := sign(ana, e2ee.TypeInvite, e2ee.Invite{ExpiresAt: expires.UnixMilli(), InviteID: "7K2MQ9XA", Inviter: bo.ID.String(), InviterIdentityPk: ana.IdentityPublicKey})
	if err := s.CreateInvite(ctx, ana.User, "7K2MQ9XA", random(32), expires, payload, sig, random(32)); !isValidation(err) {
		t.Fatalf("statement naming another inviter: %v", err)
	}
	if err := s.CreateInvite(ctx, ana.User, "ILOVEYOU", random(32), expires, payload, sig, random(32)); !isValidation(err) {
		t.Fatalf("id outside Crockford base32: %v", err)
	}

	auth := f.invite(s, ana, "7K2MQ9XA")
	if _, err := s.Invite(ctx, "7k2mq9xa"); err != nil {
		t.Fatalf("lower-case id: %v", err)
	}
	if _, err := s.CheckInvite(ctx, "7K2MQ9XA", random(32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sign-up gate with a wrong auth: %v", err)
	}

	p, sg := acceptance(bo, "7K2MQ9XA")
	if _, err := s.Redeem(ctx, bo.User, "7K2MQ9XA", random(32), p, sg); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong auth: %v", err)
	}
	if _, err := s.Redeem(ctx, cy.User, "7K2MQ9XA", auth, p, sg); !isValidation(err) {
		t.Fatalf("someone else's acceptance: %v", err)
	}
	inviter, err := s.Redeem(ctx, bo.User, "7K2MQ9XA", auth, p, sg)
	if err != nil || inviter != ana.ID {
		t.Fatalf("redeem: %v", err)
	}
	// Reusable: a second invitee joins with the same link.
	p, sg = acceptance(cy, "7K2MQ9XA")
	if _, err := s.Redeem(ctx, cy.User, "7K2MQ9XA", auth, p, sg); err != nil {
		t.Fatalf("second redemption: %v", err)
	}
	friends, _ := s.Friends(ctx, ana.ID)
	if len(friends) != 2 {
		t.Fatalf("ana has %d friends", len(friends))
	}
	p, sg = acceptance(ana, "7K2MQ9XA")
	if _, err := s.Redeem(ctx, ana.User, "7K2MQ9XA", auth, p, sg); !isValidation(err) {
		t.Fatalf("own invite: %v", err)
	}

	if err := s.RevokeInvite(ctx, bo.ID, "7K2MQ9XA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking someone else's invite: %v", err)
	}
	if err := s.RevokeInvite(ctx, ana.ID, "7K2MQ9XA"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Invite(ctx, "7K2MQ9XA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked invite: %v", err)
	}
}

func TestBlocksAndReports(t *testing.T) {
	f := setup(t)
	s := NewSocial(f.pool)
	ctx := t.Context()
	ana, bo, stranger := f.member(), f.member(), f.member()
	auth := f.invite(s, ana, "H4N8R2CJ")
	p, sg := acceptance(bo, "H4N8R2CJ")
	if _, err := s.Redeem(ctx, bo.User, "H4N8R2CJ", auth, p, sg); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Report(ctx, ana.ID, stranger.ID, "spam"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reporting a stranger: %v", err)
	}
	if _, err := s.Report(ctx, ana.ID, bo.ID, "rude name"); err != nil {
		t.Fatalf("reporting a friend: %v", err)
	}

	if err := s.Block(ctx, bo.ID, ana.ID); err != nil {
		t.Fatal(err)
	}
	if friends, _ := s.Friends(ctx, ana.ID); len(friends) != 0 {
		t.Fatal("a block leaves the friendship")
	}
	// Blocked either way: the invite cannot bring them back together, and the answer is
	// the same as for any unusable invite, so nobody learns of the block.
	if _, err := s.Redeem(ctx, bo.User, "H4N8R2CJ", auth, p, sg); !errors.Is(err, ErrNotFound) {
		t.Fatalf("redeeming the blocked person's invite: %v", err)
	}
	if _, err := s.Report(ctx, bo.ID, ana.ID, "followed me after the block"); err != nil {
		t.Fatalf("reporting someone blocked: %v", err)
	}
}

func TestStreaks(t *testing.T) {
	f := setup(t)
	s := NewSocial(f.pool)
	ctx := t.Context()
	ana, bo, stranger := f.member(), f.member(), f.member()
	auth := f.invite(s, ana, "T6PW3ZQF")
	p, sg := acceptance(bo, "T6PW3ZQF")
	if _, err := s.Redeem(ctx, bo.User, "T6PW3ZQF", auth, p, sg); err != nil {
		t.Fatal(err)
	}

	st := e2ee.Streak{Current: 42, Day: today(0), Deadline: time.Now().Add(30 * time.Hour).UnixMilli(), Longest: 42, Practice: "dorje-sempa", Seq: 1, User: ana.ID.String()}
	payload, sig := sign(ana, e2ee.TypeStreak, st)
	if _, _, err := s.PutStreak(ctx, ana.User, "mandala", payload, sig); !isValidation(err) {
		t.Fatalf("path and statement disagree: %v", err)
	}
	if _, _, err := s.PutStreak(ctx, bo.User, "dorje-sempa", payload, sig); !isValidation(err) {
		t.Fatalf("someone else's statement: %v", err)
	}
	if _, newDay, err := s.PutStreak(ctx, ana.User, "dorje-sempa", payload, sig); err != nil || !newDay {
		t.Fatalf("first statement: %v newDay=%v", err, newDay)
	}
	if _, _, err := s.PutStreak(ctx, ana.User, "dorje-sempa", payload, sig); !isConflict(err) {
		t.Fatalf("same seq: %v", err)
	}
	bad := st
	bad.Seq, bad.Longest = 2, 3
	payload, sig = sign(ana, e2ee.TypeStreak, bad)
	if _, _, err := s.PutStreak(ctx, ana.User, "dorje-sempa", payload, sig); !isValidation(err) {
		t.Fatalf("longest below current: %v", err)
	}
	// Later the same day: a newer statement, but no new day, so no "done today".
	same := st
	same.Seq = 2
	payload, sig = sign(ana, e2ee.TypeStreak, same)
	if _, newDay, err := s.PutStreak(ctx, ana.User, "dorje-sempa", payload, sig); err != nil || newDay {
		t.Fatalf("same day again: %v newDay=%v", err, newDay)
	}
	next := st
	next.Seq, next.Day, next.Current, next.Longest = 3, today(1), 43, 43
	payload, sig = sign(ana, e2ee.TypeStreak, next)
	if _, newDay, err := s.PutStreak(ctx, ana.User, "dorje-sempa", payload, sig); err != nil || !newDay {
		t.Fatalf("next day: %v newDay=%v", err, newDay)
	}

	if got, _ := s.FriendsStreaks(ctx, bo.ID); len(got) != 1 {
		t.Fatalf("a friend sees %d streaks", len(got))
	}
	if got, _ := s.FriendsStreaks(ctx, stranger.ID); len(got) != 0 {
		t.Fatal("a stranger sees the streak")
	}
	if err := s.DeleteStreak(ctx, ana.ID, "dorje-sempa"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.FriendsStreaks(ctx, bo.ID); len(got) != 0 {
		t.Fatal("a private streak is still visible")
	}
}

// fillEveryTable gives u a row in every table the server has.
func (f *fixture) fillEveryTable(s *Social) member {
	ctx := f.t.Context()
	ana, bo := f.member(), f.member()
	if err := f.q.CreateSession(ctx, db.CreateSessionParams{TokenHash: random(32), UserID: ana.ID}); err != nil {
		f.t.Fatal(err)
	}
	dev, _ := f.device(ana.User, "hardware")
	if err := f.wraps.Put(ctx, ana.User, dev.ID, signedWrap(ana.User, ana.identity, dev, e2ee.KindPracticeKey, 1)); err != nil {
		f.t.Fatal(err)
	}
	list := e2ee.DeviceList{Devices: []e2ee.Device{{ID: dev.ID.String(), PK: dev.PublicKey, Tier: "hardware"}}, IssuedAt: 1, User: ana.ID.String(), Version: 1}
	payload, sig := sign(ana, e2ee.TypeDeviceList, list)
	if err := f.devices.PutDeviceList(ctx, ana.User, payload, sig); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.logs.Put(ctx, ana.User, uuid.NewV7(), LogInput{Sealed: random(284), KeyVersion: 1, UpdatedAt: time.Now()}); err != nil {
		f.t.Fatal(err)
	}
	box, boxSig := signedBox(ana.User, ana.identity, 1)
	if err := f.recovery.Put(ctx, ana.User, 1, box, boxSig); err != nil {
		f.t.Fatal(err)
	}
	auth := f.invite(s, ana, "Q9XA7K2M")
	p, sg := acceptance(bo, "Q9XA7K2M")
	if _, err := s.Redeem(ctx, bo.User, "Q9XA7K2M", auth, p, sg); err != nil {
		f.t.Fatal(err)
	}
	// ana also redeemed someone's invite, so invite_redemptions has her as invitee.
	auth2 := f.invite(s, bo, "C6J4R8N2")
	p, sg = acceptance(ana, "C6J4R8N2")
	if _, err := s.Redeem(ctx, ana.User, "C6J4R8N2", auth2, p, sg); err != nil {
		f.t.Fatal(err)
	}
	if _, err := s.Report(ctx, ana.ID, bo.ID, "test report"); err != nil {
		f.t.Fatal(err)
	}
	stranger := f.member()
	if err := s.Block(ctx, ana.ID, stranger.ID); err != nil {
		f.t.Fatal(err)
	}
	st := e2ee.Streak{Current: 1, Day: today(0), Deadline: time.Now().Add(time.Hour).UnixMilli(), Longest: 1, Practice: "mandala", Seq: 1, User: ana.ID.String()}
	payload, sig = sign(ana, e2ee.TypeStreak, st)
	if _, _, err := s.PutStreak(ctx, ana.User, "mandala", payload, sig); err != nil {
		f.t.Fatal(err)
	}
	if err := s.UpdateProfile(ctx, ana.ID, ProfileUpdate{DisplayName: ptr("Ana"), SetUsername: true, Username: ptr("ana"),
		SetGender: true, Gender: ptr("female")}); err != nil {
		f.t.Fatal(err)
	}
	// Sign-in rows: a passkey, an e-mail identity with an unused link, a ceremony.
	if err := f.q.CreateCredential(ctx, db.CreateCredentialParams{ID: random(16), UserID: ana.ID, Data: []byte(`{}`)}); err != nil {
		f.t.Fatal(err)
	}
	email := "ana@example.com"
	if err := f.q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: "email", Subject: email, UserID: ana.ID, Email: &email}); err != nil {
		f.t.Fatal(err)
	}
	if err := f.q.CreateMagicLink(ctx, db.CreateMagicLinkParams{TokenHash: random(32), Email: email}); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.q.CreateWebauthnSession(ctx, db.CreateWebauthnSessionParams{Data: []byte(`{}`), UserID: &ana.ID}); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO admission_codes (code_hash, expires_at, used_by, used_at)
		VALUES ($1, now() + interval '1 day', $2, now())`, random(32), ana.ID); err != nil {
		f.t.Fatal(err)
	}
	nudges := NewNudges(f.pool, nil)
	if err := nudges.PutToken(ctx, ana.ID, dev.ID, "apns", boToken); err != nil {
		f.t.Fatal(err)
	}
	if err := nudges.Poke(ctx, ana.User, bo.ID); err != nil {
		f.t.Fatal(err)
	}
	return ana
}

func (f *fixture) tables() []string {
	rows, err := f.pool.Query(f.t.Context(), `SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' AND table_name <> 'goose_db_version'
		ORDER BY table_name`)
	if err != nil {
		f.t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		names = append(names, n)
	}
	return names
}

// Adding a table without deciding how it is exported fails here (design: Data
// export and deletion › Testing).
func TestExportCoversEveryTable(t *testing.T) {
	f := setup(t)
	ana := f.fillEveryTable(NewSocial(f.pool))
	tables := f.tables()
	if !slices.Equal(tables, ExportedTables) {
		t.Fatalf("tables %v, but the export covers %v: add the new table to Export", tables, ExportedTables)
	}
	export, err := NewGDPR(f.pool).Export(t.Context(), ana.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(export)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var users struct{ Username, Gender *string }
	_ = json.Unmarshal(fields["users"], &users)
	if users.Username == nil || *users.Username != "ana" || users.Gender == nil || *users.Gender != "female" {
		t.Errorf("the export lacks the username or gender: %s", fields["users"])
	}
	for _, table := range tables {
		if table == "webauthn_sessions" || table == "auth_nonces" || table == "purge_log" {
			continue // exported as always empty (see ExportedTables)
		}
		v, ok := fields[table]
		if !ok || string(v) == "null" || string(v) == "[]" {
			t.Errorf("the export has nothing under %q although the user has rows there", table)
		}
	}
}

// After a purge no row anywhere references the user (design: Data export and
// deletion › Testing); the invite tree keeps an anonymous node.
func TestPurgeLeavesNoTrace(t *testing.T) {
	f := setup(t)
	ana := f.fillEveryTable(NewSocial(f.pool))
	ctx := t.Context()
	if err := NewGDPR(f.pool).Purge(ctx, ana.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type = 'uuid'`)
	if err != nil {
		t.Fatal(err)
	}
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		_ = rows.Scan(&c.table, &c.column)
		cols = append(cols, c)
	}
	for _, c := range cols {
		var n int
		q := fmt.Sprintf(`SELECT count(*) FROM %q WHERE %q = $1`, c.table, c.column)
		if err := f.pool.QueryRow(ctx, q, ana.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s.%s still references the purged user (%d rows)", c.table, c.column, n)
		}
	}
	var links int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM magic_links WHERE email = 'ana@example.com'`).Scan(&links)
	if links != 0 {
		t.Errorf("%d unused magic links to the purged address remain", links)
	}
	var named int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username = 'ana'`).Scan(&named)
	if named != 0 {
		t.Error("the purged user's username remains")
	}
	var anonymous int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM invite_tree WHERE user_id IS NULL`).Scan(&anonymous)
	if anonymous != 1 {
		t.Fatalf("%d anonymous invite-tree nodes, want 1", anonymous)
	}
}
