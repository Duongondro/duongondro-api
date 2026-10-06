package service

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/dbtest"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

type fixture struct {
	t        *testing.T
	pool     *pgxpool.Pool
	q        *db.Queries
	accounts *Accounts
	devices  *Devices
	wraps    *Wraps
	logs     *Logs
	recovery *Recovery
}

func setup(t *testing.T) *fixture {
	pool := dbtest.Fresh(t, "service_tests")
	devices := NewDevices(pool)
	return &fixture{t: t, pool: pool, q: db.New(pool), accounts: NewAccounts(pool), devices: devices,
		wraps: NewWraps(pool, devices), logs: NewLogs(pool), recovery: NewRecovery(pool)}
}

// user creates an account with its node in the invite tree, as every account has.
func (f *fixture) user() db.User {
	u, err := f.q.CreateUser(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.q.CreateInviteNode(f.t.Context(), db.CreateInviteNodeParams{UserID: &u.ID}); err != nil {
		f.t.Fatal(err)
	}
	return u
}

func (f *fixture) reload(u db.User) db.User {
	u, err := f.q.GetUser(f.t.Context(), u.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return u
}

// withIdentity gives u an identity key and returns its private half.
func (f *fixture) withIdentity(u db.User) (db.User, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := f.accounts.SetIdentity(f.t.Context(), u, pub); err != nil {
		f.t.Fatal(err)
	}
	return f.reload(u), priv
}

func (f *fixture) device(u db.User, tier string) (db.Device, *ecdh.PrivateKey) {
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	dev, created, err := f.devices.Register(f.t.Context(), u.ID, key.PublicKey().Bytes(), tier)
	if err != nil || !created {
		f.t.Fatalf("register: %v created=%v", err, created)
	}
	return dev, key
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// signedWrap wraps a fresh secret to dev the way a client would, signed by identity.
func signedWrap(u db.User, identity ed25519.PrivateKey, dev db.Device, kind e2ee.WrapKind, version int) WrapInput {
	recipient, _ := e2ee.ParsePublicKey(dev.PublicKey)
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	aad := e2ee.WrapAAD(e2ee.UUID(u.ID), uint32(version), e2ee.UUID(dev.ID), kind)
	epk, box, err := e2ee.Wrap(recipient, eph, random(32), aad, random(e2ee.NonceSize))
	if err != nil {
		panic(err)
	}
	return WrapInput{Kind: int(kind), KeyVersion: version, EphemeralKey: epk, Box: box,
		AuthType: "signature", Authenticator: e2ee.SignWrap(identity, epk, box, aad, dev.PublicKey)}
}

func isValidation(err error) bool { _, ok := errors.AsType[*ValidationError](err); return ok }
func isConflict(err error) bool   { _, ok := errors.AsType[*ConflictError](err); return ok }

func TestIdentityIsSetOnce(t *testing.T) {
	f := setup(t)
	u := f.user()
	if err := f.accounts.SetIdentity(t.Context(), u, random(31)); !isValidation(err) {
		t.Fatalf("short key: %v", err)
	}
	u, _ = f.withIdentity(u)
	if err := f.accounts.SetIdentity(t.Context(), u, u.IdentityPublicKey); err != nil {
		t.Fatalf("same key again: %v", err)
	}
	if err := f.accounts.SetIdentity(t.Context(), u, random(32)); !isConflict(err) {
		t.Fatalf("another key: %v", err)
	}
}

func TestRegisterDevice(t *testing.T) {
	f := setup(t)
	u := f.user()
	dev, key := f.device(u, "hardware")
	again, created, err := f.devices.Register(t.Context(), u.ID, key.PublicKey().Bytes(), "hardware")
	if err != nil || created || again.ID != dev.ID {
		t.Fatalf("same key again: %v created=%v", err, created)
	}
	off := key.PublicKey().Bytes()
	off[64] ^= 1 // off the curve
	if _, _, err := f.devices.Register(t.Context(), u.ID, off, "software"); !isValidation(err) {
		t.Fatalf("off-curve key: %v", err)
	}
	if _, _, err := f.devices.Register(t.Context(), u.ID, random(65), "quantum"); !isValidation(err) {
		t.Fatalf("bad tier: %v", err)
	}
	other := f.user()
	if err := f.devices.Delete(t.Context(), other.ID, dev.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another user's device: %v", err)
	}
	if err := f.devices.Delete(t.Context(), u.ID, dev.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceList(t *testing.T) {
	f := setup(t)
	u := f.user()
	dev, _ := f.device(u, "tee")
	list := e2ee.DeviceList{Devices: []e2ee.Device{{ID: dev.ID.String(), PK: dev.PublicKey, Tier: "tee"}}, IssuedAt: 1, User: u.ID.String(), Version: 1}
	payload, _ := e2ee.Marshal(list)

	if err := f.devices.PutDeviceList(t.Context(), u, payload, random(64)); !isConflict(err) {
		t.Fatalf("without an identity key: %v", err)
	}
	u, identity := f.withIdentity(u)
	sign := func(p []byte) []byte { return e2ee.SignStatement(identity, e2ee.TypeDeviceList, p) }

	if err := f.devices.PutDeviceList(t.Context(), u, payload, random(64)); !isValidation(err) {
		t.Fatalf("bad signature: %v", err)
	}
	if err := f.devices.PutDeviceList(t.Context(), u, payload, sign(payload)); err != nil {
		t.Fatalf("valid list: %v", err)
	}
	if err := f.devices.PutDeviceList(t.Context(), u, payload, sign(payload)); !isConflict(err) {
		t.Fatalf("same version again: %v", err)
	}

	spaced := append([]byte(" "), payload...)
	if err := f.devices.PutDeviceList(t.Context(), u, spaced, sign(spaced)); !isValidation(err) {
		t.Fatalf("non-canonical payload: %v", err)
	}
	stranger := list
	stranger.Version = 2
	stranger.Devices = []e2ee.Device{{ID: uuid.NewV7().String(), PK: dev.PublicKey, Tier: "tee"}}
	p2, _ := e2ee.Marshal(stranger)
	if err := f.devices.PutDeviceList(t.Context(), u, p2, sign(p2)); !isValidation(err) {
		t.Fatalf("unregistered device: %v", err)
	}
	lied := list
	lied.Version = 2
	lied.Devices = []e2ee.Device{{ID: dev.ID.String(), PK: dev.PublicKey, Tier: "hardware"}}
	p3, _ := e2ee.Marshal(lied)
	if err := f.devices.PutDeviceList(t.Context(), u, p3, sign(p3)); !isValidation(err) {
		t.Fatalf("wrong tier: %v", err)
	}
	stored, err := f.devices.DeviceList(t.Context(), u.ID)
	if err != nil || stored.Version != 1 {
		t.Fatalf("stored list: %v %+v", err, stored)
	}
}

func TestWraps(t *testing.T) {
	f := setup(t)
	u := f.user()
	dev, _ := f.device(u, "hardware")
	u, identity := f.withIdentity(u)

	w := signedWrap(u, identity, dev, e2ee.KindPracticeKey, 1)
	if err := f.wraps.Put(t.Context(), u, dev.ID, w); err != nil {
		t.Fatalf("signed wrap: %v", err)
	}
	// The AAD binds the device: the same wrap to another device fails the signature.
	other, _ := f.device(u, "software")
	if err := f.wraps.Put(t.Context(), u, other.ID, w); !isValidation(err) {
		t.Fatalf("wrap moved to another device: %v", err)
	}
	if err := f.wraps.Put(t.Context(), u, dev.ID, signedWrap(u, identity, dev, e2ee.KindPracticeKey, 2)); !isValidation(err) {
		t.Fatalf("future key version: %v", err)
	}
	enrol := signedWrap(u, identity, other, e2ee.KindIdentitySeed, 1)
	enrol.AuthType, enrol.Authenticator = "enrol", random(32)
	if err := f.wraps.Put(t.Context(), u, other.ID, enrol); err != nil {
		t.Fatalf("enrolment wrap: %v", err)
	}
	enrol.Authenticator = random(31)
	if err := f.wraps.Put(t.Context(), u, other.ID, enrol); !isValidation(err) {
		t.Fatalf("short tag: %v", err)
	}
	stranger := f.user()
	if err := f.wraps.Put(t.Context(), stranger, dev.ID, w); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another user's device: %v", err)
	}
	wraps, err := f.wraps.List(t.Context(), u.ID, dev.ID)
	if err != nil || len(wraps) != 1 {
		t.Fatalf("list: %v %d", err, len(wraps))
	}
}

func TestRotation(t *testing.T) {
	f := setup(t)
	u := f.user()
	a, _ := f.device(u, "hardware")
	b, _ := f.device(u, "software")
	u, identity := f.withIdentity(u)
	for _, d := range []db.Device{a, b} {
		if err := f.wraps.Put(t.Context(), u, d.ID, signedWrap(u, identity, d, e2ee.KindPracticeKey, 1)); err != nil {
			t.Fatal(err)
		}
	}
	rw := func(d db.Device) RotationWrap {
		return RotationWrap{DeviceID: d.ID, WrapInput: signedWrap(u, identity, d, e2ee.KindPracticeKey, 2)}
	}
	if err := f.wraps.Rotate(t.Context(), u, 2, []RotationWrap{rw(a)}); !isValidation(err) {
		t.Fatalf("leaving a device out: %v", err)
	}
	if err := f.wraps.Rotate(t.Context(), u, 3, []RotationWrap{rw(a), rw(b)}); !isConflict(err) {
		t.Fatalf("skipping a version: %v", err)
	}
	if err := f.wraps.Rotate(t.Context(), u, 2, []RotationWrap{rw(a), rw(b)}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	u = f.reload(u)
	if u.KeyVersion != 2 {
		t.Fatalf("key version %d", u.KeyVersion)
	}
	// A log sealed under version 1 is now refused with the current version.
	_, err := f.logs.Put(t.Context(), u, uuid.NewV7(), LogInput{Sealed: random(284), KeyVersion: 1, UpdatedAt: time.Now()})
	if old, ok := errors.AsType[*OldKeyError](err); !ok || old.Current != 2 {
		t.Fatalf("old key: %v", err)
	}
}

func TestLogsAndSync(t *testing.T) {
	f := setup(t)
	u := f.user()
	ctx := t.Context()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	id := uuid.NewV7()

	if _, err := f.logs.Put(ctx, u, uuid.New(), LogInput{Sealed: random(284), KeyVersion: 1, UpdatedAt: t0}); !isValidation(err) {
		t.Fatalf("v4 id: %v", err)
	}
	for _, n := range []int{283, 300, 284 + 16384 + 256} {
		if _, err := f.logs.Put(ctx, u, id, LogInput{Sealed: random(n), KeyVersion: 1, UpdatedAt: t0}); !isValidation(err) {
			t.Fatalf("sealed of %d bytes: %v", n, err)
		}
	}

	first, err := f.logs.Sync(ctx, u.ID, "")
	if err != nil || !first.Full || len(first.Logs) != 0 {
		t.Fatalf("empty sync: %v %+v", err, first)
	}
	cursor := FormatCursor(first.Cursor)

	v1 := random(284)
	if _, err := f.logs.Put(ctx, u, id, LogInput{Sealed: v1, KeyVersion: 1, UpdatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	// An older write loses and gets the stored row back.
	row, err := f.logs.Put(ctx, u, id, LogInput{Sealed: random(540), KeyVersion: 1, UpdatedAt: t0.Add(-time.Minute)})
	if err != nil || string(row.Sealed) != string(v1) {
		t.Fatalf("older write: %v", err)
	}
	changes, err := f.logs.Sync(ctx, u.ID, cursor)
	if err != nil || changes.Full || len(changes.Logs) != 1 {
		t.Fatalf("incremental sync: %v full=%v n=%d", err, changes.Full, len(changes.Logs))
	}

	// Another user can neither see nor overwrite it.
	other := f.user()
	if _, err := f.logs.Put(ctx, other, id, LogInput{Sealed: random(284), KeyVersion: 1, UpdatedAt: time.Now()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another user's log: %v", err)
	}
	if theirs, _ := f.logs.Sync(ctx, other.ID, ""); len(theirs.Logs) != 0 {
		t.Fatal("another user's sync sees the log")
	}

	// A deletion is a sealed tombstone: without one it is refused.
	if _, err := f.logs.Put(ctx, u, id, LogInput{Deleted: true, KeyVersion: 1, UpdatedAt: t0.Add(time.Minute)}); !isValidation(err) {
		t.Fatalf("unsealed deletion: %v", err)
	}
	tomb := random(284)
	row, err = f.logs.Put(ctx, u, id, LogInput{Sealed: tomb, Deleted: true, KeyVersion: 1, UpdatedAt: t0.Add(time.Minute)})
	if err != nil || string(row.Sealed) != string(tomb) || row.DeletedAt == nil {
		t.Fatalf("deletion: %v %+v", err, row)
	}
	// A clock far ahead would block every later edit until then.
	if _, err := f.logs.Put(ctx, u, id, LogInput{Sealed: tomb, KeyVersion: 1, UpdatedAt: time.Now().Add(time.Hour)}); !isValidation(err) {
		t.Fatalf("updatedAt an hour ahead: %v", err)
	}

	// A cursor from another database generation means a full sync.
	if _, err := f.pool.Exec(ctx, "UPDATE database_generation SET id = uuidv7()"); err != nil {
		t.Fatal(err)
	}
	restored, err := f.logs.Sync(ctx, u.ID, FormatCursor(changes.Cursor))
	if err != nil || !restored.Full || len(restored.Logs) != 1 {
		t.Fatalf("after a restore: %v %+v", err, restored)
	}
	if _, err := f.logs.Sync(ctx, u.ID, "not-a-cursor"); !isValidation(err) {
		t.Fatalf("malformed cursor: %v", err)
	}
}

func signedBox(u db.User, identity ed25519.PrivateKey, kind int) ([]byte, []byte) {
	box := random(60)
	return box, e2ee.SignRecoveryBox(identity, e2ee.UUID(u.ID), e2ee.WrapKind(kind), box)
}

func TestRecovery(t *testing.T) {
	f := setup(t)
	u := f.user()
	if err := f.recovery.Put(t.Context(), u, 1, random(60), random(64)); !isConflict(err) {
		t.Fatalf("without an identity key: %v", err)
	}
	u, identity := f.withIdentity(u)
	if err := f.recovery.Put(t.Context(), u, 3, random(60), random(64)); !isValidation(err) {
		t.Fatalf("share keys have no recovery box: %v", err)
	}
	if err := f.recovery.Put(t.Context(), u, 1, random(60), random(64)); !isValidation(err) {
		t.Fatalf("a box a session made up: %v", err)
	}
	for kind := 1; kind <= 2; kind++ {
		b, sig := signedBox(u, identity, kind)
		if err := f.recovery.Put(t.Context(), u, kind, b, sig); err != nil {
			t.Fatal(err)
		}
	}
	boxes, err := f.recovery.List(t.Context(), u.ID)
	if err != nil || len(boxes) != 2 {
		t.Fatalf("boxes: %v %d", err, len(boxes))
	}
}

// today is the UTC civil day offset days from now, for streak statements whose
// deadline the tests take from the clock.
func today(offset int) string {
	return time.Now().UTC().AddDate(0, 0, offset).Format("2006-01-02")
}
