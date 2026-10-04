package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

// userColumn is a column with a foreign key to users(id).
type userColumn struct{ Table, Column string }

// userColumns derives, from information_schema, every column of the test
// schema that references users(id). A new table with such a column must be
// handled by Export and Purge, or the tests below fail.
func userColumns(t *testing.T, s *store.Store) []userColumn {
	t.Helper()
	rows, err := s.Pool().Query(context.Background(), `
		SELECT DISTINCT kcu.table_name::text, kcu.column_name::text
		FROM information_schema.referential_constraints rc
		JOIN information_schema.key_column_usage kcu
			ON kcu.constraint_schema = rc.constraint_schema AND kcu.constraint_name = rc.constraint_name
		JOIN information_schema.constraint_column_usage ccu
			ON ccu.constraint_schema = rc.unique_constraint_schema AND ccu.constraint_name = rc.unique_constraint_name
		WHERE kcu.table_schema = current_schema()
			AND ccu.table_name = 'users' AND ccu.column_name = 'id'
		ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (userColumn, error) {
		var c userColumn
		return c, r.Scan(&c.Table, &c.Column)
	})
	if err != nil {
		t.Fatal(err)
	}
	// The users table itself, by its primary key.
	cols = append([]userColumn{{Table: "users", Column: "id"}}, cols...)
	if len(cols) < 15 {
		t.Fatalf("found only %d user columns: %v", len(cols), cols)
	}
	return cols
}

// Every uuid column is either a reference to users or one of these, so a
// user column cannot dodge the checks by lacking a foreign key.
var nonUserUUIDs = map[string]bool{
	"users.id": true, "devices.id": true, "practice_logs.id": true, "database_generation.id": true,
	"sessions.device_id": true, "push_tokens.device_id": true, "wraps.recipient_device": true,
}

func TestEveryUUIDColumnIsAccountedFor(t *testing.T) {
	s := newStore(t)
	refs := map[string]bool{}
	for _, c := range userColumns(t, s) {
		refs[c.Table+"."+c.Column] = true
	}
	rows, err := s.Pool().Query(context.Background(), `SELECT table_name::text || '.' || column_name::text
		FROM information_schema.columns WHERE table_schema = current_schema() AND data_type = 'uuid'`)
	if err != nil {
		t.Fatal(err)
	}
	cols, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if !refs[c] && !nonUserUUIDs[c] {
			t.Errorf("%s is a uuid column without a foreign key to users: add one (and export/purge it) or list it in nonUserUUIDs", c)
		}
	}
}

type fixture struct {
	Victim, Friend, Other string
	Session               []byte
}

func p256(t *testing.T, seed byte) []byte {
	t.Helper()
	// The P-256 generator with its last byte varied: the store checks only
	// sizes (the server checks points), and keys must differ per device.
	g := []byte{0x04,
		0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
		0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
		0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
		0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5}
	out := append([]byte(nil), g...)
	out[64] ^= seed
	return out
}

// populate gives the victim a row in every table that references users.
func populate(t *testing.T, s *store.Store) fixture {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	f := fixture{Victim: mkUser(t, s, "Victim"), Friend: mkUser(t, s, "Friend"), Other: mkUser(t, s, "Other")}
	identity := bytes.Repeat([]byte{7}, 32)
	_, err := s.Pool().Exec(ctx, `UPDATE users SET identity_pk = $1, avatar_ref = 'avatars/v' WHERE id = $2`, identity, f.Victim)
	must(err)

	must(s.AddEmailIdentity(ctx, f.Victim, "victim@example.org"))
	_, err = s.Pool().Exec(ctx, `INSERT INTO auth_identities (user_id, provider, subject) VALUES ($1, 'apple', 'apple-subject-1')`, f.Victim)
	must(err)
	must(s.CreateMagicLink(ctx, sha(t, "ml"), "victim@example.org", time.Now().Add(time.Hour)))
	must(s.CreateSignupToken(ctx, sha(t, "st"), "victim@example.org", time.Now().Add(time.Hour)))

	_, f.Session = ids.NewToken()
	must(s.CreateSession(ctx, f.Session, f.Victim))
	vDev := ids.NewV7().String()
	_, _, err = s.RegisterDevice(ctx, f.Victim, f.Session, store.Device{ID: vDev, PublicKey: p256(t, 1), Tier: "hardware"})
	must(err)
	_, fSession := ids.NewToken()
	must(s.CreateSession(ctx, fSession, f.Friend))
	fDev := ids.NewV7().String()
	_, _, err = s.RegisterDevice(ctx, f.Friend, fSession, store.Device{ID: fDev, PublicKey: p256(t, 2), Tier: "tee"})
	must(err)

	_, err = s.PublishDeviceList(ctx, store.DeviceList{UserID: f.Victim, Version: 1, Payload: []byte(`{}`), Signature: make([]byte, 64), IdentityPK: identity},
		[]store.ListedDevice{{ID: vDev, PublicKey: p256(t, 1), Tier: "hardware"}})
	must(err)

	wrap := func(user, device, sender string, kind int16) store.Wrap {
		return store.Wrap{UserID: user, KeyVersion: 1, RecipientDevice: device, Kind: kind, SenderID: sender,
			EPK: p256(t, 3), Box: make([]byte, 60), AuthenticatorKind: "signature", Authenticator: make([]byte, 64)}
	}
	must(s.PutWrap(ctx, wrap(f.Victim, vDev, f.Victim, 1)))
	must(s.PutWrap(ctx, wrap(f.Victim, vDev, f.Friend, 3))) // the friend's share key to the victim
	must(s.PutWrap(ctx, wrap(f.Friend, fDev, f.Victim, 3))) // the victim's share key to the friend
	must(s.PutRecoveryBox(ctx, f.Victim, 1, make([]byte, 60)))

	_, _, err = s.PutPracticeLog(ctx, store.PracticeLog{ID: ids.NewV7().String(), UserID: f.Victim, Sealed: sealed(1), KeyVersion: 1, UpdatedAt: time.Now()})
	must(err)
	_, _, err = s.PublishStreak(ctx, store.StreakStatement{UserID: f.Victim, Practice: "dorje-sempa", Seq: 1, Day: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC),
		Current: 3, Longest: 3, Deadline: time.Now(), Payload: []byte(`{}`), Signature: make([]byte, 64)})
	must(err)

	// The friend invited the victim; the victim invited the other.
	invite := func(inviter string) (string, []byte) {
		id, key := ids.NewInviteID(), bytes.Repeat([]byte{byte(len(inviter))}, 32)
		h := sha256.Sum256(key)
		must(s.CreateInvite(ctx, store.Invite{ID: id, InviterID: inviter, AuthKeyHash: h[:], Payload: []byte(`{}`), Signature: make([]byte, 64), MAC: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}))
		return id, key
	}
	acc := store.Acceptance{Payload: []byte(`{"accept":1}`), Signature: make([]byte, 64)}
	fi, fk := invite(f.Friend)
	_, err = s.RedeemInvite(ctx, time.Now(), fi, f.Victim, fk, acc)
	must(err)
	vi, vk := invite(f.Victim)
	_, err = s.RedeemInvite(ctx, time.Now(), vi, f.Other, vk, acc)
	must(err)

	must(s.BlockUser(ctx, f.Victim, f.Other))
	must(s.BlockUser(ctx, f.Friend, f.Victim))
	note := "spam"
	must(s.Report(ctx, f.Victim, f.Other, "spam", &note))
	must(s.Report(ctx, f.Other, f.Victim, "name", nil))
	must(s.PutPushToken(ctx, store.PushToken{DeviceID: vDev, UserID: f.Victim, Platform: "apns", Token: "victim-token"}))
	must(s.Poke(ctx, f.Victim, f.Friend, time.Now()))
	must(s.Poke(ctx, f.Friend, f.Victim, time.Now()))
	return f
}

func sha(t *testing.T, s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func countRefs(t *testing.T, s *store.Store, c userColumn, id string) int {
	t.Helper()
	var n int
	q := `SELECT count(*) FROM ` + pgx.Identifier{c.Table}.Sanitize() + ` WHERE ` + pgx.Identifier{c.Column}.Sanitize() + ` = $1`
	if err := s.Pool().QueryRow(context.Background(), q, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// (a) After a purge, no column that references users holds the id.
func TestPurgeLeavesNoReference(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	f := populate(t, s)
	cols := userColumns(t, s)

	// The fixture must touch every table, or the check below proves little.
	touched := map[string]bool{}
	for _, c := range cols {
		if countRefs(t, s, c, f.Victim) > 0 {
			touched[c.Table] = true
		}
	}
	for _, c := range cols {
		if !touched[c.Table] {
			t.Errorf("fixture has no row in %s referencing the victim: extend populate()", c.Table)
		}
	}

	subjects, err := s.Purge(ctx, f.Victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 1 || subjects[0] != "apple-subject-1" {
		t.Fatalf("apple subjects %v", subjects)
	}
	for _, c := range cols {
		if n := countRefs(t, s, c, f.Victim); n != 0 {
			t.Errorf("%s.%s still holds the purged id in %d rows", c.Table, c.Column, n)
		}
	}
	// Pending links to the user's address are gone too.
	var links int
	if err := s.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_links WHERE email = 'victim@example.org') + (SELECT count(*) FROM signup_tokens WHERE email = 'victim@example.org')`).Scan(&links); err != nil || links != 0 {
		t.Fatalf("links to the purged address: %d %v", links, err)
	}

	// The invite tree keeps its shape through one nameless placeholder.
	var inviterOfOther, inviteeOfFriend, reported string
	var acceptance []byte
	if err := s.Pool().QueryRow(ctx, `SELECT inviter_id::text FROM invite_redemptions WHERE invitee_id = $1`, f.Other).Scan(&inviterOfOther); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool().QueryRow(ctx, `SELECT invitee_id::text, acceptance_payload FROM invite_redemptions WHERE inviter_id = $1`, f.Friend).Scan(&inviteeOfFriend, &acceptance); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool().QueryRow(ctx, `SELECT reported_id::text FROM reports WHERE reporter_id = $1`, f.Other).Scan(&reported); err != nil {
		t.Fatal(err)
	}
	if inviterOfOther != inviteeOfFriend || inviterOfOther != reported || acceptance != nil {
		t.Fatalf("placeholder: %s %s %s %x", inviterOfOther, inviteeOfFriend, reported, acceptance)
	}
	var name string
	var placeholder bool
	if err := s.Pool().QueryRow(ctx, `SELECT display_name, placeholder FROM users WHERE id = $1`, inviterOfOther).Scan(&name, &placeholder); err != nil || name != "" || !placeholder {
		t.Fatalf("placeholder row %q %v %v", name, placeholder, err)
	}
	if ok, _ := s.UserExists(ctx, inviterOfOther); ok {
		t.Fatal("a placeholder counts as an account")
	}

	// The purge log holds only the hash; a restored backup purges again.
	uid, _ := ids.ParseUUID(f.Victim)
	var logged int
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM purge_log WHERE user_hash = $1`, uid.Hash()).Scan(&logged); err != nil || logged != 1 {
		t.Fatalf("purge log %d %v", logged, err)
	}
	if _, err := s.Pool().Exec(ctx, `INSERT INTO users (id, display_name) VALUES ($1, 'Restored')`, f.Victim); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ReapplyPurges(ctx); err != nil || n != 1 {
		t.Fatalf("reapply %d %v", n, err)
	}
	if ok, _ := s.UserExists(ctx, f.Victim); ok {
		t.Fatal("restored account survived reapplying purges")
	}
	if _, err := s.Purge(ctx, f.Victim); err != store.ErrNotFound {
		t.Fatalf("second purge: %v", err)
	}

	// Others are untouched.
	if ok, _ := s.UserExists(ctx, f.Friend); !ok {
		t.Fatal("friend purged")
	}
}

// (b) The export has a key for every table that references users.
func TestExportCoversEveryUserTable(t *testing.T) {
	s := newStore(t)
	f := populate(t, s)
	tables, err := s.Export(context.Background(), f.Victim)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, c := range userColumns(t, s) {
		want[c.Table] = true
	}
	for tbl := range want {
		rows, ok := tables[tbl]
		if !ok {
			t.Errorf("export lacks table %s", tbl)
		} else if len(rows) == 0 {
			t.Errorf("export of %s is empty for a user with rows there", tbl)
		}
	}
	var extra []string
	for tbl := range tables {
		if !want[tbl] {
			extra = append(extra, tbl)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("export has tables without a user column: %v", extra)
	}

	// Secrets that are not data about the person are left out, and
	// encodings follow the contract.
	if _, ok := tables["sessions"][0]["token_hash"]; ok {
		t.Error("session token hash exported")
	}
	if _, ok := tables["invites"][0]["auth_key_hash"]; ok {
		t.Error("invite auth key hash exported")
	}
	user := tables["users"][0]
	if user["id"] != f.Victim || user["display_name"] != "Victim" || !strings.HasSuffix(user["created_at"].(string), "Z") {
		t.Errorf("users row %v", user)
	}
	if user["identity_pk"] != "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=" {
		t.Errorf("bytea not standard base64: %v", user["identity_pk"])
	}
	if _, ok := tables["practice_logs"][0]["xid"].(string); !ok {
		t.Errorf("xid8 not a string: %T", tables["practice_logs"][0]["xid"])
	}
	if tables["streak_statements"][0]["day"] != "2026-10-04" {
		t.Errorf("date %v", tables["streak_statements"][0]["day"])
	}
	// Blocks and reports: only those the victim made.
	for _, b := range tables["blocks"] {
		if b["blocker_id"] != f.Victim {
			t.Errorf("exported someone else's block: %v", b)
		}
	}
	for _, r := range tables["reports"] {
		if r["reporter_id"] != f.Victim {
			t.Errorf("exported a report about the victim: %v", r)
		}
	}
	if len(tables["nudges"]) != 2 || len(tables["wraps"]) != 3 || len(tables["invite_redemptions"]) != 2 {
		t.Errorf("sent and received rows: nudges %d wraps %d redemptions %d", len(tables["nudges"]), len(tables["wraps"]), len(tables["invite_redemptions"]))
	}
	if got := store.ExportTables(); len(got) != len(want) {
		t.Errorf("ExportTables %v", got)
	}
}
