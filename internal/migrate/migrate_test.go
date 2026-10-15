package migrate_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Duongondro/duongondro-api/db/migrations"
	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/dbtest"
	"github.com/Duongondro/duongondro-api/internal/migrate"
	"github.com/Duongondro/duongondro-api/internal/service/names"
)

// beforeAtRest is the last migration before encryption at rest: production's schema
// when it ships.
const beforeAtRest = 20261007052551

func upTo(t *testing.T, pool *pgxpool.Pool, keys *atrest.Keys, version int64) {
	t.Helper()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.GooseFS(), goose.WithGoMigrations(migrations.Go(keys)...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), version); err != nil {
		t.Fatal(err)
	}
}

// A database with rows in every plain personal column, as production has them, is
// sealed by the migrations: every value opens to what it was (addresses normalised),
// the blind indexes find it, and the plain columns are gone.
func TestMigrationSealsExistingRows(t *testing.T) {
	pool := dbtest.Empty(t, "migrate_tests")
	keys := dbtest.Keys()
	ctx := t.Context()
	upTo(t, pool, keys, beforeAtRest)

	ana, bo := uuid.NewV7(), uuid.NewV7()
	dev := uuid.NewV7()
	report := uuid.NewV7()
	identityKey, deviceKey := bytes.Repeat([]byte{1}, 32), append([]byte{4}, bytes.Repeat([]byte{2}, 64)...)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO users (id, identity_public_key, display_name, username, gender) VALUES ($1, $2, 'Ana', 'ana', 'female'), ($3, NULL, '', NULL, NULL)`,
		ana, identityKey, bo)
	exec(`INSERT INTO devices (id, user_id, public_key, tier) VALUES ($1, $2, $3, 'hardware')`, dev, ana, deviceKey)
	exec(`INSERT INTO device_lists (user_id, version, payload, signature) VALUES ($1, 1, '{"list":1}', $2)`, ana, make([]byte, 64))
	exec(`INSERT INTO invites (id, inviter_id, auth_hash, payload, signature, mac, expires_at)
		VALUES ('Q9XA7K2M', $1, $2, '{"invite":1}', $3, $2, now() + interval '1 day')`, ana, make([]byte, 32), make([]byte, 64))
	exec(`INSERT INTO invite_redemptions (invite_id, invitee_id, payload, signature) VALUES ('Q9XA7K2M', $1, '{"accept":1}', $2)`, bo, make([]byte, 64))
	exec(`INSERT INTO reports (id, reporter_id, reported_id, reason) VALUES ($1, $2, $3, 'rude')`, report, bo, ana)
	exec(`INSERT INTO streaks (user_id, practice, seq, payload, signature, deadline_at) VALUES ($1, 'mandala', 1, '{"streak":1}', $2, now())`,
		ana, make([]byte, 64))
	exec(`INSERT INTO credentials (id, user_id, data) VALUES ('\x0102'::bytea, $1, '{"passkey": true}')`, ana)
	exec(`INSERT INTO webauthn_sessions (data, user_id, display_name) VALUES ('{}', $1, 'Ana')`, ana)
	// Stored lower-cased by the old code, but not NFC: e and a combining acute.
	exec(`INSERT INTO auth_identities (provider, subject, user_id, email, refresh_token) VALUES
		('email', 'zoe`+"́"+`@example.com', $1, 'zoe`+"́"+`@example.com', NULL),
		('apple', '001234.abc', $1, 'ana@icloud.com', 'refresh-me')`, ana)
	exec(`INSERT INTO magic_links (token_hash, email) VALUES ($1, 'ana@example.com')`, bytes.Repeat([]byte{9}, 32))
	exec(`INSERT INTO push_tokens (device_id, platform, token) VALUES ($1, 'apns', 'abcdef0123456789abcdef0123456789')`, dev)

	if err := migrate.Up(ctx, pool, keys); err != nil {
		t.Fatalf("migrating the rows: %v", err)
	}
	q := db.New(pool)

	u, err := keys.User(q.GetUser(ctx, ana))
	if err != nil || !bytes.Equal(u.IdentityPublicKey, identityKey) || u.DisplayName != "Ana" || *u.Username != "ana" || *u.Gender != "female" {
		t.Fatalf("users: %+v %v", u, err)
	}
	if taken, _ := q.UsernameTaken(ctx, keys.HashString("ana")); !taken {
		t.Error("the username's blind index does not find it")
	}
	// An empty profile: sealed as NULLs, then named by NameUnnamedAccounts.
	if u, err := keys.User(q.GetUser(ctx, bo)); err != nil || !isRandomName(u.DisplayName) || u.Username != nil || u.Gender != nil || u.IdentityPublicKey != nil {
		t.Errorf("an empty profile: %+v %v", u, err)
	}
	if d, err := keys.Device(q.GetDeviceByKey(ctx, db.GetDeviceByKeyParams{UserID: ana, PublicKeyHash: keys.Hash(deviceKey)})); err != nil ||
		d.ID != dev || !bytes.Equal(d.PublicKey, deviceKey) {
		t.Errorf("devices: %+v %v", d, err)
	}
	if l, err := keys.DeviceList(q.GetDeviceList(ctx, ana)); err != nil || string(l.Payload) != `{"list":1}` {
		t.Errorf("device_lists: %v", err)
	}
	if i, err := keys.Invite(q.GetLiveInvite(ctx, "Q9XA7K2M")); err != nil || string(i.Payload) != `{"invite":1}` {
		t.Errorf("invites: %v", err)
	}
	if r, err := keys.InviteRedemptions(q.ExportRedemptions(ctx, bo)); err != nil || len(r) != 1 || string(r[0].Payload) != `{"accept":1}` {
		t.Errorf("invite_redemptions: %v", err)
	}
	if r, err := keys.Reports(q.ExportReports(ctx, bo)); err != nil || len(r) != 1 || r[0].Reason != "rude" {
		t.Errorf("reports: %v", err)
	}
	if s, err := keys.Streak(q.GetStreak(ctx, db.GetStreakParams{UserID: ana, PracticeHash: keys.HashString("mandala")})); err != nil ||
		s.Practice != "mandala" || string(s.Payload) != `{"streak":1}` {
		t.Errorf("streaks: %+v %v", s, err)
	}
	if c, err := keys.Credentials(q.ListCredentials(ctx, ana)); err != nil || len(c) != 1 || string(c[0].Data) != `{"passkey": true}` {
		t.Errorf("credentials: %v", err)
	}
	var ceremonies int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM webauthn_sessions`).Scan(&ceremonies)
	if ceremonies != 0 {
		t.Errorf("%d passkey ceremonies survived", ceremonies)
	}
	zoe := atrest.NormaliseEmail("zoé@example.com")
	if zoe != "zoé@example.com" {
		t.Fatalf("NFC: %q", zoe)
	}
	if i, err := keys.Identity(q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", SubjectHash: keys.HashString(zoe)})); err != nil ||
		i.Subject != zoe || *i.Email != zoe {
		t.Errorf("an e-mail identity, normalised: %+v %v", i, err)
	}
	if i, err := keys.Identity(q.GetIdentity(ctx, db.GetIdentityParams{Provider: "apple", SubjectHash: keys.HashString("001234.abc")})); err != nil ||
		*i.Email != "ana@icloud.com" || *i.RefreshToken != "refresh-me" {
		t.Errorf("an Apple identity: %+v %v", i, err)
	}
	var links int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM magic_links WHERE email_hash = $1`, keys.HashString("ana@example.com")).Scan(&links)
	if links != 1 {
		t.Errorf("magic_links by hash: %d", links)
	}
	if p, err := keys.PushTokens(q.PushTokensOf(ctx, ana)); err != nil || len(p) != 1 || p[0].Token != "abcdef0123456789abcdef0123456789" ||
		!bytes.Equal(p[0].TokenHash, keys.HashString(p[0].Token)) {
		t.Errorf("push_tokens: %v", err)
	}

	var plain int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema()
		AND (table_name, column_name) IN (('users', 'display_name'), ('users', 'username'), ('auth_identities', 'email'),
			('magic_links', 'email'), ('push_tokens', 'token'), ('streaks', 'practice'), ('reports', 'reason'))`).Scan(&plain)
	if plain != 0 {
		t.Errorf("%d plain columns remain", plain)
	}
}

// Migrating again, with a previous key configured, reseals: the rotation runs as part
// of `server migrate`.
func TestMigrateReseals(t *testing.T) {
	pool := dbtest.Fresh(t, "migrate_reseal_tests")
	ctx := t.Context()
	keys := dbtest.Keys()
	id := uuid.NewV7()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, display_name_encrypted) VALUES ($1, $2)`, id, keys.SealDisplayName(id, "Ana")); err != nil {
		t.Fatal(err)
	}
	newBase := []byte("a new SECRET_KEY_BASE for the migrate test, 32+ bytes")
	rotating, _ := atrest.New(newBase, dbtest.SecretKeyBase)
	if err := migrate.Up(ctx, pool, rotating); err != nil {
		t.Fatal(err)
	}
	after, _ := atrest.New(newBase, nil)
	if u, err := after.User(db.New(pool).GetUser(ctx, id)); err != nil || u.DisplayName != "Ana" {
		t.Fatalf("after the rotation: %+v %v", u, err)
	}
}

// Sealing and dropping the plain columns commit together: when anything fails after
// the rows are sealed (here the drop, blocked by a view on a plain column), nothing of
// step 2 is applied, the plain values are untouched, and a later migrate succeeds.
func TestFailedSealLeavesPlainColumns(t *testing.T) {
	pool := dbtest.Empty(t, "migrate_fail_tests")
	keys := dbtest.Keys()
	ctx := t.Context()
	upTo(t, pool, keys, beforeAtRest)
	ana := uuid.NewV7()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, display_name, username) VALUES ($1, 'Ana', 'ana')`, ana); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE VIEW names AS SELECT display_name FROM users`); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, pool, keys); err == nil {
		t.Fatal("the drop succeeded despite a view on display_name")
	}
	var version int64
	_ = pool.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version)
	if version != 20261014183130 {
		t.Fatalf("applied up to %d, want only step 1 (20261014183130)", version)
	}
	var name, username string
	var sealed []byte
	if err := pool.QueryRow(ctx, `SELECT display_name, username, display_name_encrypted FROM users WHERE id = $1`, ana).
		Scan(&name, &username, &sealed); err != nil || name != "Ana" || username != "ana" || sealed != nil {
		t.Fatalf("after the failure: %q %q sealed=%x %v", name, username, sealed, err)
	}
	if _, err := pool.Exec(ctx, `DROP VIEW names`); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, pool, keys); err != nil {
		t.Fatalf("migrating again: %v", err)
	}
	if u, err := keys.User(db.New(pool).GetUser(ctx, ana)); err != nil || u.DisplayName != "Ana" || *u.Username != "ana" {
		t.Fatalf("after the retry: %+v %v", u, err)
	}
}

// Two e-mail identities that are one address once normalised stop the migration
// before it changes anything, naming the accounts.
func TestEmailCollisionFailsFast(t *testing.T) {
	pool := dbtest.Empty(t, "migrate_collision_tests")
	keys := dbtest.Keys()
	ctx := t.Context()
	upTo(t, pool, keys, beforeAtRest)
	a, b := uuid.NewV7(), uuid.NewV7()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id) VALUES ($1), ($2)`, a, b); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth_identities (provider, subject, user_id) VALUES
		('email', 'zo`+"é"+`@example.com', $1), ('email', 'zoe`+"́"+`@example.com', $2)`, a, b); err != nil {
		t.Fatal(err)
	}
	err := migrate.Up(ctx, pool, keys)
	if err == nil || !strings.Contains(err.Error(), a.String()) || !strings.Contains(err.Error(), b.String()) ||
		strings.Contains(err.Error(), "example.com") {
		t.Fatalf("want a failure naming both accounts and no address: %v", err)
	}
	var version int64
	var subjects int
	_ = pool.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM auth_identities WHERE subject_encrypted IS NULL AND subject IS NOT NULL`).Scan(&subjects)
	if version != 20261014183130 || subjects != 2 {
		t.Fatalf("applied up to %d with %d plain subjects", version, subjects)
	}
	// The preflight SQL in docs/at-rest.md finds the same pair.
	var pairs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT lower(normalize(subject, NFC)) FROM auth_identities
		WHERE provider = 'email' GROUP BY 1 HAVING count(*) > 1) clashes`).Scan(&pairs); err != nil || pairs != 1 {
		t.Fatalf("the preflight SQL: %d pairs, %v", pairs, err)
	}
}

// A table someone else holds (a backup's pg_dump) is skipped after lock_timeout, not
// waited on forever; the rest are rewritten and migrate goes on.
func TestRewriteSkipsALockedTable(t *testing.T) {
	pool := dbtest.Empty(t, "migrate_rewrite_tests")
	keys := dbtest.Keys()
	ctx := t.Context()
	upTo(t, pool, keys, 20261014183131)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.GooseFS(), goose.WithGoMigrations(
		migrations.EncryptColumnsBackfill(keys), migrations.RewriteEncryptedTables(200*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("with users locked: %v", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("took %s: the lock was waited on", took)
	}
	sources := p.ListSources()
	if v, _ := p.GetDBVersion(ctx); v != sources[len(sources)-1].Version {
		t.Fatalf("at version %d", v)
	}
}

// isRandomName reports whether name is an adjective and an animal from the lists.
func isRandomName(name string) bool {
	adj, animal, ok := strings.Cut(name, " ")
	return ok && slices.Contains(names.Adjectives, adj) && slices.Contains(names.Animals, animal)
}

// Accounts made before sign-up named them get a random name, sealed, at the next
// migrate: those without one, or with one that shows as blank. Named accounts keep
// theirs, and migrating again changes nothing.
func TestMigrationNamesUnnamedAccounts(t *testing.T) {
	pool := dbtest.Empty(t, "migrate_names_tests")
	keys := dbtest.Keys()
	ctx := t.Context()
	upTo(t, pool, keys, 20261015204739)
	ana, none, blank := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()
	for id, name := range map[uuid.UUID]string{ana: "Ana", none: "", blank: "\u200b \u200e"} {
		if _, err := pool.Exec(ctx, `INSERT INTO users (id, display_name_encrypted) VALUES ($1, $2)`, id, keys.SealDisplayName(id, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrate.Up(ctx, pool, keys); err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	nameOf := func(id uuid.UUID) string {
		t.Helper()
		u, err := keys.User(q.GetUser(ctx, id))
		if err != nil {
			t.Fatal(err)
		}
		return u.DisplayName
	}
	if nameOf(ana) != "Ana" {
		t.Fatalf("a named account was renamed: %q", nameOf(ana))
	}
	first := map[uuid.UUID]string{}
	for _, id := range []uuid.UUID{none, blank} {
		if first[id] = nameOf(id); !isRandomName(first[id]) {
			t.Fatalf("%s: %q", id, first[id])
		}
	}
	var sealed []byte
	if err := pool.QueryRow(ctx, `SELECT display_name_encrypted FROM users WHERE id = $1`, none).Scan(&sealed); err != nil ||
		bytes.Contains(sealed, []byte(first[none])) {
		t.Fatalf("the name is not sealed: %v", err)
	}
	if err := migrate.Up(ctx, pool, keys); err != nil {
		t.Fatal(err)
	}
	for id, name := range first {
		if nameOf(id) != name {
			t.Fatalf("migrating again renamed %s", id)
		}
	}
}
