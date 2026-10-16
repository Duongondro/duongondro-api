package service

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

// userKey is a user key U as a phone makes one: a fresh id and key pair, published
// at the given version.
type userKey struct {
	id      uuid.UUID
	key     *ecdh.PrivateKey
	version int64
}

func (f *fixture) newUserKey(m member, version int64) (userKey, []byte, []byte) {
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	uk := userKey{id: uuid.NewV7(), key: key, version: version}
	payload, sig := sign(m, e2ee.TypeUserKey, e2ee.UserKey{ID: uk.id.String(), PK: key.PublicKey().Bytes(), User: m.ID.String(), Version: version})
	return uk, payload, sig
}

// publishUserKey publishes U with the practice key and identity seed wrapped to it.
func (f *fixture) publishUserKey(u *Unlock, m member, version int64) userKey {
	return f.replaceUserKey(u, m, version, nil)
}

// replaceUserKey publishes U as publishUserKey does, replacing the stored one from
// the given device when it is not nil.
func (f *fixture) replaceUserKey(u *Unlock, m member, version int64, device *uuid.UUID) userKey {
	f.t.Helper()
	uk, payload, sig := f.newUserKey(m, version)
	replaced, err := u.PutUserKey(f.t.Context(), m.User, UserKeyInput{Payload: payload, Signature: sig, Replace: device != nil, Device: device})
	if err != nil || replaced != (device != nil) {
		f.t.Fatalf("user key: %v (replaced %v)", err, replaced)
	}
	for _, kind := range []e2ee.WrapKind{e2ee.KindPracticeKey, e2ee.KindIdentitySeed} {
		if err := u.PutUserKeyWrap(f.t.Context(), m.User, wrapToUserKey(m, uk, kind, 1)); err != nil {
			f.t.Fatalf("wrap to the user key: %v", err)
		}
	}
	return uk
}

func wrapToUserKey(m member, uk userKey, kind e2ee.WrapKind, version int) UserKeyWrapInput {
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	aad := e2ee.WrapAAD(e2ee.UUID(m.ID), uint32(version), e2ee.UUID(uk.id), kind)
	epk, box, err := e2ee.Wrap(uk.key.PublicKey(), eph, random(32), aad, random(e2ee.NonceSize))
	if err != nil {
		panic(err)
	}
	return UserKeyWrapInput{UserKeyID: uk.id, Kind: int(kind), KeyVersion: version, EphemeralKey: epk, Box: box,
		Signature: e2ee.SignWrap(m.identity, epk, box, aad, uk.key.PublicKey().Bytes())}
}

// passkeyBox seals U's scalar under a made-up PRF output for one passkey.
func passkeyBox(m member, uk userKey, credentialID []byte) (box, sig []byte) {
	aad := e2ee.PasskeyBoxAAD(e2ee.UUID(m.ID), e2ee.UUID(uk.id), credentialID)
	box, err := e2ee.SealPasskeyBox(e2ee.PRFKey(random(32), e2ee.UUID(m.ID)), aad, uk.key.Bytes(), random(e2ee.NonceSize))
	if err != nil {
		panic(err)
	}
	return box, e2ee.SignPasskeyBox(m.identity, aad, box)
}

func (f *fixture) credential(userID uuid.UUID) []byte {
	f.t.Helper()
	id := random(16)
	if err := f.q.CreateCredential(f.t.Context(), db.CreateCredentialParams{ID: id, UserID: userID,
		DataEncrypted: f.keys.Seal(atrest.CredentialsData, atrest.RowOf(id), []byte(`{}`))}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestUserKey(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	u := NewUnlock(f.pool, f.keys)
	ana, bo := f.member(), f.member()

	if _, _, err := u.UserKey(ctx, ana.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no user key yet: %v", err)
	}
	if err := u.PutUserKeyWrap(ctx, ana.User, UserKeyWrapInput{UserKeyID: uuid.NewV7(), Kind: 1, KeyVersion: 1}); !isConflict(err) {
		t.Fatalf("a wrap before any user key: %v", err)
	}

	// The statement: signed by the account's own identity key, naming it, canonical.
	_, payload, _ := f.newUserKey(ana, 1)
	_, _, bosSig := f.newUserKey(bo, 1)
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: payload, Signature: bosSig}); !isValidation(err) {
		t.Fatalf("someone else's signature: %v", err)
	}
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	other, otherSig := sign(ana, e2ee.TypeUserKey, e2ee.UserKey{ID: uuid.NewV7().String(), PK: key.PublicKey().Bytes(), User: bo.ID.String(), Version: 1})
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: other, Signature: otherSig}); !isValidation(err) {
		t.Fatalf("a statement naming another user: %v", err)
	}
	offCurve := append([]byte{}, key.PublicKey().Bytes()...)
	offCurve[64] ^= 1
	bad, badSig := sign(ana, e2ee.TypeUserKey, e2ee.UserKey{ID: uuid.NewV7().String(), PK: offCurve, User: ana.ID.String(), Version: 1})
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: bad, Signature: badSig}); !isValidation(err) {
		t.Fatalf("a key off the curve: %v", err)
	}
	spaced := append([]byte(" "), payload...)
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: spaced, Signature: e2ee.SignStatement(ana.identity, e2ee.TypeUserKey, spaced)}); !isValidation(err) {
		t.Fatalf("a payload not in canonical form: %v", err)
	}

	first := f.publishUserKey(u, ana, 1)
	got, wraps, err := u.UserKey(ctx, ana.ID)
	if err != nil || got.ID != first.id || got.Version != 1 || len(wraps) != 2 {
		t.Fatalf("user key: %v %+v %d wraps", err, got, len(wraps))
	}

	// Wraps to U: signed over U's id and key, at a version the account has.
	w := wrapToUserKey(ana, first, e2ee.KindPracticeKey, 1)
	w.Signature = wrapToUserKey(bo, first, e2ee.KindPracticeKey, 1).Signature
	if err := u.PutUserKeyWrap(ctx, ana.User, w); !isValidation(err) {
		t.Fatalf("a wrap signed by someone else: %v", err)
	}
	if err := u.PutUserKeyWrap(ctx, ana.User, wrapToUserKey(ana, first, e2ee.KindPracticeKey, 2)); !isValidation(err) {
		t.Fatalf("a future key version: %v", err)
	}
	if err := u.PutUserKeyWrap(ctx, ana.User, wrapToUserKey(ana, first, e2ee.KindUserKey, 1)); !isValidation(err) {
		t.Fatalf("U wrapped to itself: %v", err)
	}

	// A passkey's box: only the account's passkeys, signed over the current U.
	phone, bos := f.credential(ana.ID), f.credential(bo.ID)
	box, sig := passkeyBox(ana, first, phone)
	if err := u.PutPasskeyBox(ctx, ana.User, bos, first.id, box, sig); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a box for someone else's passkey: %v", err)
	}
	if err := u.PutPasskeyBox(ctx, ana.User, phone, first.id, box, e2ee.SignPasskeyBox(ana.identity, random(48), box)); !isValidation(err) {
		t.Fatalf("a signature over another AAD: %v", err)
	}
	if err := u.PutPasskeyBox(ctx, ana.User, phone, uuid.NewV7(), box, sig); !isConflict(err) {
		t.Fatalf("a box for another user key: %v", err)
	}
	if err := u.PutPasskeyBox(ctx, ana.User, phone, first.id, box, sig); err != nil {
		t.Fatal(err)
	}
	unlock, err := u.PasskeyBox(ctx, ana.ID, phone)
	if err != nil || string(unlock.Box) != string(box) || unlock.UserKey.ID != first.id || len(unlock.Wraps) != 2 {
		t.Fatalf("unlock: %v %+v", err, unlock)
	}
	if _, err := u.PasskeyBox(ctx, bo.ID, phone); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account reads the box: %v", err)
	}

	// A new U needs a higher version and a new id, and drops the old one's boxes
	// and wraps, including its copies on the account's phones.
	dev, _ := f.device(ana.User, "hardware")
	if err := f.wraps.Put(ctx, ana.User, dev.ID, signedWrap(ana.User, ana.identity, dev, e2ee.KindUserKey, 2)); !isConflict(err) {
		t.Fatalf("a kind 4 wrap at another version than U's: %v", err)
	}
	selfTagged := signedWrap(ana.User, ana.identity, dev, e2ee.KindUserKey, 1)
	selfTagged.AuthType, selfTagged.Authenticator = "self", random(32)
	if err := f.wraps.Put(ctx, ana.User, dev.ID, selfTagged); !isValidation(err) {
		t.Fatalf("an unsigned kind 4 wrap: %v", err)
	}
	if err := f.wraps.Put(ctx, ana.User, dev.ID, signedWrap(ana.User, ana.identity, dev, e2ee.KindUserKey, 1)); err != nil {
		t.Fatalf("U to a phone: %v", err)
	}
	// Publishing is a conditional create: a second U is refused, never stored over
	// the first, and that phone waits for the first one as a kind 4 wrap.
	_, newer, newerSig := f.newUserKey(ana, 2)
	var exists *UserKeyExistsError
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: newer, Signature: newerSig}); !errors.As(err, &exists) || exists.ID != first.id || exists.Version != 1 {
		t.Fatalf("a second user key without replace: %v", err)
	}
	// Replacing needs replace and a phone holding the current practice key.
	stranger, _ := f.device(ana.User, "hardware")
	for _, device := range []*uuid.UUID{nil, &stranger.ID} {
		if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: newer, Signature: newerSig, Replace: true, Device: device}); !isConflict(err) || errors.As(err, &exists) {
			t.Fatalf("a replacement from a phone without the keys (%v): %v", device, err)
		}
	}
	if err := f.wraps.Put(ctx, ana.User, dev.ID, signedWrap(ana.User, ana.identity, dev, e2ee.KindPracticeKey, 1)); err != nil {
		t.Fatal(err)
	}
	_, stale, staleSig := f.newUserKey(ana, 1)
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: stale, Signature: staleSig, Replace: true, Device: &dev.ID}); !isConflict(err) {
		t.Fatalf("a replacement at the same version: %v", err)
	}
	if _, wraps, _ := u.UserKey(ctx, ana.ID); len(wraps) != 2 || wraps[0].UserKeyID != first.id {
		t.Fatalf("a refused U changed the stored one: %+v", wraps)
	}
	second := f.replaceUserKey(u, ana, 2, &dev.ID)
	if _, err := u.PasskeyBox(ctx, ana.ID, phone); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the old U's box outlived it: %v", err)
	}
	if _, wraps, _ := u.UserKey(ctx, ana.ID); len(wraps) != 2 || wraps[0].UserKeyID != second.id {
		t.Fatalf("wraps after replacing U: %+v", wraps)
	}
	if onPhone, _ := f.wraps.List(ctx, ana.ID, dev.ID); len(onPhone) != 1 || onPhone[0].Kind != int16(e2ee.KindPracticeKey) {
		t.Fatalf("the old U stayed on the phone: %+v", onPhone)
	}
	if err := u.PutUserKeyWrap(ctx, ana.User, wrapToUserKey(ana, first, e2ee.KindPracticeKey, 1)); !isConflict(err) {
		t.Fatalf("a wrap to the replaced U: %v", err)
	}

	// Settings shows which passkeys unlock; removing a box or the passkey ends it.
	box, sig = passkeyBox(ana, second, phone)
	if err := u.PutPasskeyBox(ctx, ana.User, phone, second.id, box, sig); err != nil {
		t.Fatal(err)
	}
	laptop := f.credential(ana.ID)
	s, _ := f.signIn(nil, nil, nil)
	keys, err := s.Passkeys(ctx, ana.ID, nil)
	if err != nil || len(keys) != 2 || !keys[0].CanUnlock || keys[1].CanUnlock {
		t.Fatalf("passkeys: %v %+v", err, keys)
	}
	if err := u.DeletePasskeyBox(ctx, bo.ID, phone); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account removes the box: %v", err)
	}
	box, sig = passkeyBox(ana, second, laptop)
	if err := u.PutPasskeyBox(ctx, ana.User, laptop, second.id, box, sig); err != nil {
		t.Fatal(err)
	}
	if err := u.DeletePasskeyBox(ctx, ana.ID, laptop); err != nil {
		t.Fatal(err)
	}
	if err := s.RemovePasskey(ctx, ana.ID, phone); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.q.ExportPasskeyBoxes(ctx, ana.ID); len(n) != 0 {
		t.Fatalf("boxes left after removing the passkey: %d", len(n))
	}
}

// A rotation carries the new practice key to U while U holds the current one.
func TestRotationWrapsToUserKey(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	u := NewUnlock(f.pool, f.keys)
	ana := f.member()
	dev, _ := f.device(ana.User, "hardware")
	if err := f.wraps.Put(ctx, ana.User, dev.ID, signedWrap(ana.User, ana.identity, dev, e2ee.KindPracticeKey, 1)); err != nil {
		t.Fatal(err)
	}
	devices := []RotationWrap{{DeviceID: dev.ID, WrapInput: signedWrap(ana.User, ana.identity, dev, e2ee.KindPracticeKey, 2)}}
	uk := f.publishUserKey(u, ana, 1)
	if err := f.wraps.Rotate(ctx, ana.User, 2, devices, nil); !isValidation(err) {
		t.Fatalf("a rotation leaving U out: %v", err)
	}
	identitySeed := wrapToUserKey(ana, uk, e2ee.KindIdentitySeed, 2)
	if err := f.wraps.Rotate(ctx, ana.User, 2, devices, &identitySeed); !isValidation(err) {
		t.Fatalf("a rotation wrapping the identity seed to U: %v", err)
	}
	toU := wrapToUserKey(ana, uk, e2ee.KindPracticeKey, 2)
	if err := f.wraps.Rotate(ctx, ana.User, 2, devices, &toU); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if _, wraps, _ := u.UserKey(ctx, ana.ID); len(wraps) != 3 || wraps[1].KeyVersion != 2 {
		t.Fatalf("wraps to U after the rotation: %+v", wraps)
	}

	// Without a user key, a wrap to one is refused.
	bo := f.member()
	if err := f.wraps.Rotate(ctx, bo.User, 2, nil, &toU); !isConflict(err) {
		t.Fatalf("a rotation wrapping to a user key that does not exist: %v", err)
	}
}

// The first phone's U wins; sending the same statement again is a safe retry, and
// another phone's U is refused with the stored one's id, without replacing it.
func TestUserKeyFirstPhoneWins(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	u := NewUnlock(f.pool, f.keys)
	ana := f.member()
	_, payload, sig := f.newUserKey(ana, 1)
	for range 2 {
		if replaced, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: payload, Signature: sig}); err != nil || replaced {
			t.Fatalf("publishing U: %v (replaced %v)", err, replaced)
		}
	}
	stored, _, _ := u.UserKey(ctx, ana.ID)
	_, other, otherSig := f.newUserKey(ana, 1)
	var exists *UserKeyExistsError
	if _, err := u.PutUserKey(ctx, ana.User, UserKeyInput{Payload: other, Signature: otherSig}); !errors.As(err, &exists) || exists.ID != stored.ID {
		t.Fatalf("a second phone's U: %v", err)
	}
	if got, _, _ := u.UserKey(ctx, ana.ID); got.ID != stored.ID || string(got.Payload) != string(payload) {
		t.Fatalf("the stored U changed: %+v", got)
	}
}
