package db_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/db/dbtest"
)

func TestMigrationsAreOrdered(t *testing.T) {
	ms, err := db.Migrations()
	if err != nil || len(ms) == 0 {
		t.Fatalf("migrations: %v %d", err, len(ms))
	}
	for i, m := range ms {
		if len(m.Version) < 5 || m.Version[4] != '_' {
			t.Errorf("%s: name migrations NNNN_description.sql", m.Version)
		}
		if i > 0 && ms[i-1].Version >= m.Version {
			t.Errorf("%s out of order", m.Version)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	applied, err := db.Migrate(ctx, pool)
	if err != nil || len(applied) != 0 {
		t.Fatalf("second migrate applied %v: %v", applied, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM database_generation`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("generation rows %d: %v", n, err)
	}
}

func TestChecks(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	const user = "0190f3a1-7b2c-7d4e-8f00-123456789abc"
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, display_name) VALUES ($1, 'Tenzin')`, user); err != nil {
		t.Fatal(err)
	}
	pk := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{"empty name", `INSERT INTO users (id, display_name) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000001', '')`, nil},
		{"named placeholder", `INSERT INTO users (id, display_name, placeholder) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000001', 'x', true)`, nil},
		{"short identity key", `UPDATE users SET identity_pk = $1`, []any{make([]byte, 31)}},
		{"short device key", `INSERT INTO devices (id, user_id, public_key, tier) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000002', $1, $2, 'hardware')`, []any{user, pk[:64]}},
		{"unknown tier", `INSERT INTO devices (id, user_id, public_key, tier) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000002', $1, $2, 'enclave')`, []any{user, pk}},
		{"unpadded log", `INSERT INTO practice_logs (id, user_id, sealed, key_version, client_updated_at) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000003', $1, $2, 1, now())`, []any{user, make([]byte, 300)}},
		{"oversized log", `INSERT INTO practice_logs (id, user_id, sealed, key_version, client_updated_at) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000003', $1, $2, 1, now())`, []any{user, make([]byte, 28+256*64)}},
		{"self friendship", `INSERT INTO friendships (user_a, user_b) VALUES ($1, $1)`, []any{user}},
		{"lowercase invite id", `INSERT INTO invites (id, inviter_id, auth_key_hash, payload, signature, mac, expires_at) VALUES ('7k2mq9xa', $1, $2, '{}', $3, $2, now())`, []any{user, make([]byte, 32), make([]byte, 64)}},
		{"second generation", `INSERT INTO database_generation (singleton, id) VALUES (true, gen_random_uuid())`, nil},
	}
	for _, c := range cases {
		if _, err := pool.Exec(ctx, c.sql, c.args...); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), "violates") {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
	}
	// The largest padded size is accepted.
	if _, err := pool.Exec(ctx, `INSERT INTO practice_logs (id, user_id, sealed, key_version, client_updated_at) VALUES ('0190f3a1-7b2c-7d4e-8f00-000000000003', $1, $2, 1, now())`, user, make([]byte, 28+256*63)); err != nil {
		t.Fatalf("63 blocks refused: %v", err)
	}
}
