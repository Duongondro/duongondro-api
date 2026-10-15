package service

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/dbtest"
)

// plainColumns are the text, bytea and json columns deliberately left plain, each
// with the reason (design: Backend and sync › Encryption at rest: plain are only
// random ids and the links between them, timestamps, enum values, sizes, hashes and
// what is end-to-end sealed). The sealed columns and blind indexes come from
// atrest.Tables.
var plainColumns = map[string]string{
	"admission_codes.code_hash":    "SHA-256 of an admission code",
	"auth_identities.provider":     "enum: apple, google, email",
	"auth_nonces.nonce_hash":       "SHA-256 of a sign-in nonce",
	"credentials.id":               "a passkey's credential id: random, from the authenticator, and the lookup key",
	"device_lists.signature":       "Ed25519 signature; reveals nothing without the sealed payload",
	"devices.tier":                 "enum: hardware, tee, software",
	"downloads.platform":           "enum: android",
	"invite_redemptions.invite_id": "a random invite id, the link between redemption and invite",
	"invite_redemptions.signature": "Ed25519 signature; reveals nothing without the sealed payload",
	"invites.auth_hash":            "SHA-256 of the invite's auth",
	"invites.id":                   "a random invite id (40 bits, from the link)",
	"invites.mac":                  "HMAC tag of the inviter's key under the link's pin, checked by the invitee",
	"invites.signature":            "Ed25519 signature; reveals nothing without the sealed payload",
	"key_wraps.auth_type":          "enum: signature, enrol, self",
	"key_wraps.authenticator":      "signature or HMAC tag of an end-to-end sealed wrap",
	"key_wraps.box":                "end-to-end sealed",
	"key_wraps.ephemeral_key":      "one-time public key of an end-to-end sealed wrap",
	"magic_links.code_hash":        "HMAC of the typed code under a per-process key",
	"magic_links.invite_id":        "a random invite id",
	"magic_links.token_hash":       "SHA-256 of the link's token",
	"practice_logs.sealed":         "end-to-end sealed",
	"purge_log.user_hash":          "SHA-256 of a purged account's id",
	"push_tokens.platform":         "enum: apns, apns-sandbox, fcm",
	"recovery_boxes.box":           "end-to-end sealed",
	"recovery_boxes.signature":     "Ed25519 signature over an end-to-end sealed box",
	"sessions.token_hash":          "SHA-256 of a bearer token",
	"streaks.signature":            "Ed25519 signature; reveals nothing without the sealed payload",
	"webauthn_sessions.data":       "passkey ceremony state: challenge, relying party and account id, no personal data; five minutes",
	"webauthn_sessions.invite_id":  "a random invite id",
}

// A new text, bytea or json column fails the build until it is sealed, made a blind
// index, or listed above with the reason it may stay plain; as the GDPR tests do for
// tables.
func TestEveryColumnIsClassified(t *testing.T) {
	f := setup(t)
	rows, err := f.pool.Query(t.Context(), `SELECT table_name || '.' || column_name, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name <> 'goose_db_version'
			AND data_type IN ('text', 'bytea', 'json', 'jsonb', 'character varying', 'character', 'USER-DEFINED', 'ARRAY')`)
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatal(err)
		}
		actual[name] = typ
	}
	classified := map[string]string{}
	for name, reason := range plainColumns {
		classified[name] = "plain: " + reason
	}
	for _, table := range atrest.Tables {
		for _, c := range table.Sealed {
			classified[c.String()] = "sealed"
		}
		for _, ix := range table.Indexes {
			classified[ix.Column.String()] = "blind index"
		}
	}
	for name, typ := range actual {
		kind, ok := classified[name]
		switch {
		case !ok:
			t.Errorf("%s (%s) is not classified: seal it (atrest.Tables), make it a blind index, or list it in "+
				"plainColumns with the reason it holds no personal data", name, typ)
		case kind != "sealed" && kind != "blind index":
		case typ != "bytea":
			t.Errorf("%s is %s, but a %s column is bytea", name, typ, kind)
		}
	}
	for name := range classified {
		if _, ok := actual[name]; !ok {
			t.Errorf("%s is classified but no longer exists", name)
		}
	}
}

// The restore-from-backup check: a pg_dump of a database holding a row in every table
// shows none of the values sealed at rest, in plain or as bytea hex.
func TestDumpRevealsNoSealedPlaintext(t *testing.T) {
	f := setup(t)
	pgDump, err := exec.LookPath("pg_dump")
	if err != nil {
		t.Skip("pg_dump is not installed")
	}
	ctx := t.Context()
	ana := f.fillEveryTable(NewSocial(f.pool, f.keys))
	// An Apple identity with a refresh token, which fillEveryTable has none of.
	hash := f.keys.HashString("001234.apple-subject.0987")
	row := atrest.IdentityRow("apple", hash)
	refresh := "r0a1b2c3-apple-refresh-token"
	if err := f.q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: "apple", UserID: ana.ID,
		SubjectEncrypted: f.keys.SealString(atrest.AuthIdentitiesSubject, row, "001234.apple-subject.0987"), SubjectHash: hash,
		RefreshTokenEncrypted: f.keys.SealString(atrest.AuthIdentitiesRefreshToken, row, refresh)}); err != nil {
		t.Fatal(err)
	}

	// Every sealed value, read back through the service as the export shows them.
	export, err := NewGDPR(f.pool, f.keys).Export(ctx, ana.ID)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string][]byte{
		"display name": []byte(export.Users.DisplayName), "username": []byte(*export.Users.Username),
		"gender": []byte(*export.Users.Gender), "identity key": export.Users.IdentityPublicKey,
		"report reason": []byte(export.Reports[0].Reason), "push token": []byte(boToken),
		"passkey data": []byte(`ana's passkey`), "ceremony name": []byte("Ana mid-ceremony"),
		"apple subject": []byte("001234.apple-subject.0987"), "refresh token": []byte(refresh),
		"device list": export.DeviceLists.Payload,
	}
	for _, d := range export.Devices {
		secrets["device key "+d.ID.String()] = d.PublicKey
	}
	for _, i := range export.Invites {
		secrets["invite "+i.ID] = i.Payload
	}
	for _, r := range export.InviteRedemptions {
		secrets["redemption "+r.InviteID] = r.Payload
	}
	for _, s := range export.Streaks {
		secrets["practice"], secrets["streak"] = []byte(s.Practice), s.Payload
	}
	for _, i := range export.AuthIdentities {
		secrets["subject "+i.Provider] = []byte(i.Subject)
	}
	for _, m := range export.MagicLinks {
		secrets["magic link to "+m.Email] = []byte(m.Email)
	}
	for _, fr := range export.Friendships {
		secrets["friend's key"] = fr.IdentityPublicKey
	}
	if len(export.Devices) == 0 || len(export.Invites) == 0 || len(export.Streaks) == 0 || len(export.AuthIdentities) < 2 ||
		len(export.MagicLinks) < 2 || len(export.Friendships) == 0 {
		t.Fatal("fillEveryTable no longer fills what this test checks")
	}

	schema := "service_tests"
	cmd := exec.CommandContext(ctx, pgDump, "--no-owner", "--schema="+schema, os.Getenv("TEST_DATABASE_URL"))
	dump, err := cmd.Output()
	if err != nil {
		t.Fatalf("pg_dump: %v", err)
	}
	if !bytes.Contains(dump, []byte("COPY "+schema+".users")) {
		t.Fatalf("the dump has no users:\n%.2000s", dump)
	}
	lower := bytes.ToLower(dump)
	for name, v := range secrets {
		if len(v) == 0 {
			t.Errorf("%s is empty: nothing to look for", name)
			continue
		}
		if bytes.Contains(lower, bytes.ToLower(v)) {
			t.Errorf("the dump shows the %s in plain", name)
		}
		// As bytea hex; short values only as text, since 3 bytes of hex turn up by
		// chance in kilobytes of ciphertext.
		if len(v) >= 8 && bytes.Contains(dump, []byte(hex.EncodeToString(v))) {
			t.Errorf("the dump shows the %s as hex", name)
		}
	}
}

// A rotation: with the new key current and the old one previous, Reseal rewrites
// every value and blind index, and afterwards the new key alone serves everything.
func TestResealRotatesEveryValue(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	ana := f.fillEveryTable(NewSocial(f.pool, f.keys))
	before, err := NewGDPR(f.pool, f.keys).Export(ctx, ana.ID)
	if err != nil {
		t.Fatal(err)
	}
	newBase := []byte("the next SECRET_KEY_BASE, after a rotation, for tests")
	rotating, err := atrest.New(newBase, dbtest.SecretKeyBase)
	if err != nil {
		t.Fatal(err)
	}
	n, err := atrest.Reseal(ctx, f.pool, rotating)
	if err != nil || n == 0 {
		t.Fatalf("reseal: %d rows, %v", n, err)
	}
	if again, err := atrest.Reseal(ctx, f.pool, rotating); err != nil || again != 0 {
		t.Fatalf("a second reseal rewrote %d rows: %v", again, err)
	}

	rotated, _ := atrest.New(newBase, nil)
	after, err := NewGDPR(f.pool, rotated).Export(ctx, ana.ID)
	if err != nil {
		t.Fatalf("the export under the new key alone: %v", err)
	}
	before.ExportedAt = after.ExportedAt
	if b, a := mustJSON(t, before), mustJSON(t, after); b != a {
		t.Fatalf("the export changed across the rotation:\n%s\n%s", b, a)
	}
	// Lookups by blind index use the new key.
	var links, named int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM magic_links WHERE email_hash = $1`, rotated.HashString("ana@example.com")).Scan(&links)
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username_hash = $1`, rotated.HashString("ana")).Scan(&named)
	if links != 1 || named != 1 {
		t.Fatalf("by the new hashes: %d links, %d users", links, named)
	}
	s := NewSocial(f.pool, rotated)
	if err := s.DeleteStreak(ctx, ana.ID, "mandala"); err != nil {
		t.Fatalf("a streak by its new practice hash: %v", err)
	}
	if tokens, err := rotated.PushTokens(f.q.PushTokensOf(ctx, ana.ID)); err != nil || len(tokens) != 1 || tokens[0].Token != boToken {
		t.Fatalf("push tokens under the new key: %v %v", tokens, err)
	}
	// The old key alone opens nothing any more.
	if _, err := NewGDPR(f.pool, f.keys).Export(ctx, ana.ID); err == nil {
		t.Fatal("the old key still opens the export")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The payload bounds the plain columns' CHECKs enforced, now in the service: 2 to
// 4096 bytes for invites, acceptances and streaks, 2 to 16384 for device lists.
func TestPayloadSizes(t *testing.T) {
	f := setup(t)
	s := NewSocial(f.pool, f.keys)
	ctx := t.Context()
	ana := f.member()
	sizeErr := func(err error, max int) bool {
		return isValidation(err) && strings.Contains(err.Error(), fmt.Sprintf("2 to %d bytes", max))
	}
	for _, n := range []int{0, 1, 4097} {
		p := bytes.Repeat([]byte{'x'}, n)
		if err := s.CreateInvite(ctx, ana.User, "Q9XA7K2M", random(32), time.Now().Add(time.Hour), p, random(64), random(32)); !sizeErr(err, 4096) {
			t.Errorf("an invite of %d bytes: %v", n, err)
		}
		if _, err := s.Redeem(ctx, ana.User, "Q9XA7K2M", random(32), p, random(64)); !sizeErr(err, 4096) {
			t.Errorf("an acceptance of %d bytes: %v", n, err)
		}
		if _, _, err := s.PutStreak(ctx, ana.User, "mandala", p, random(64)); !sizeErr(err, 4096) {
			t.Errorf("a streak of %d bytes: %v", n, err)
		}
	}
	for _, n := range []int{1, 16385} {
		if err := f.devices.PutDeviceList(ctx, ana.User, bytes.Repeat([]byte{'x'}, n), random(64)); !sizeErr(err, 16384) {
			t.Errorf("a device list of %d bytes: %v", n, err)
		}
	}
	// Within the bounds, the size is not what refuses an unsigned payload.
	if err := f.devices.PutDeviceList(ctx, ana.User, bytes.Repeat([]byte{'x'}, 16384), random(64)); err == nil || sizeErr(err, 16384) {
		t.Errorf("a device list of 16384 bytes: %v", err)
	}
}
