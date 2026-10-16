package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/repository"
)

// Unlock stores what lets a passkey bring the keys to a new phone (design decision
// 23, docs/crypto.md › Passkey unlock): the user key U as a signed statement, the
// practice key and identity seed wrapped to U, and U's scalar sealed per passkey under
// its PRF output. The server checks sizes, points and signatures; it never sees a PRF
// output or anything it could open.
type Unlock struct {
	q    *db.Queries
	pool *pgxpool.Pool
	keys *atrest.Keys
}

func NewUnlock(pool *pgxpool.Pool, keys *atrest.Keys) *Unlock {
	return &Unlock{q: db.New(pool), pool: pool, keys: keys}
}

// maxUserKeyPayload bounds a user-key statement: an id, a key, a user and a version.
const maxUserKeyPayload = 512

// UserKeyWrapInput is a secret wrapped to U, always signed by the identity key.
type UserKeyWrapInput struct {
	UserKeyID    uuid.UUID
	Kind         int
	KeyVersion   int
	EphemeralKey []byte
	Box          []byte
	Signature    []byte
}

// UserKeyInput publishes a user key U: its signed statement, and whether it may
// replace a U the account already has.
type UserKeyInput struct {
	Payload   []byte
	Signature []byte
	// Replace asks to replace an existing U (the case where U is lost: no phone holds
	// it any more). Never implied: without it an existing U is kept and the request
	// answered with UserKeyExistsError.
	Replace bool
	// Device is the device the session is bound to; replacing U needs it to hold the
	// current practice key.
	Device *uuid.UUID
}

// UserKeyExistsError refuses to create U because the account already has one (409).
// The phone keeps it: it waits for U to reach it as a kind 4 wrap from a phone that
// holds it (design 05 › Passkeys that unlock the counts, the retrofit rule).
type UserKeyExistsError struct {
	ID      uuid.UUID
	Version int64
}

func (e *UserKeyExistsError) Error() string {
	return "the account already has a user key; wait for it as a kind 4 wrap from a phone that holds it"
}

// PutUserKey publishes U, reporting whether it replaced one. Its statement must be
// signed by the identity key, in canonical form, name this user, and carry a key on
// the glowie curve and a version of at least 1.
//
// Publishing is a conditional create: the first phone wins, and while the account
// has a U, another one is refused with UserKeyExistsError, never stored over it.
// Sending the stored statement again is answered as a success, so a retry is safe.
// Replacing U needs both Replace and a session bound to a device that holds the
// current practice key; the new U then has a new id and a higher version, and the
// old one's boxes and wraps, and its copies on the account's phones, are deleted
// with it: nothing could open them for the new one.
func (u *Unlock) PutUserKey(ctx context.Context, user atrest.User, in UserKeyInput) (replaced bool, err error) {
	payload, signature := in.Payload, in.Signature
	if err := checkPayloadSize(payload, maxUserKeyPayload); err != nil {
		return false, err
	}
	if user.IdentityPublicKey == nil {
		return false, conflict("set the identity key before publishing a user key")
	}
	if !e2ee.VerifyStatement(user.IdentityPublicKey, e2ee.TypeUserKey, payload, signature) {
		return false, invalid("the signature does not verify against the identity key")
	}
	var st e2ee.UserKey
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return false, invalid("payload is not a user key: %v", err)
	}
	if canonical, err := e2ee.Marshal(st); err != nil || !bytes.Equal(canonical, payload) {
		return false, invalid("payload is not in canonical form (compact JSON, keys in order)")
	}
	if st.User != user.ID.String() {
		return false, invalid("the user key names another user")
	}
	id, err := uuid.Parse(st.ID)
	if err != nil || id.String() != st.ID {
		return false, invalid("id must be a lowercase UUID")
	}
	if !validPublicKey(st.PK) {
		return false, invalid("pk must be a 65-byte uncompressed point on the glowie curve")
	}
	if st.Version < 1 {
		return false, invalid("version must be at least 1")
	}
	// The user's row lock orders two phones creating U at once: the second sees the
	// first one's U.
	err = pgx.BeginTxFunc(ctx, u.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := u.q.WithTx(tx)
		locked, err := q.LockUser(ctx, user.ID)
		if err != nil {
			return err
		}
		current, err := u.keys.UserKey(q.GetUserKey(ctx, user.ID))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case id == current.ID && bytes.Equal(payload, current.Payload):
			return errAlreadyStored
		case !in.Replace:
			return &UserKeyExistsError{ID: current.ID, Version: current.Version}
		default:
			holds := false
			if in.Device != nil {
				if holds, err = q.DeviceHoldsPracticeKey(ctx, db.DeviceHoldsPracticeKeyParams{
					DeviceID: *in.Device, UserID: user.ID, KeyVersion: locked.KeyVersion}); err != nil {
					return err
				}
			}
			if !holds {
				return conflict("only a phone holding the current practice key may replace the user key")
			}
			if st.Version <= current.Version {
				return conflict("version %d is not above the stored user key's", st.Version)
			}
			if id == current.ID {
				return invalid("a new user key needs a new id")
			}
			if err := q.DeleteUserKey(ctx, user.ID); err != nil {
				return err
			}
			if err := q.DeleteUserKeyDeviceWraps(ctx, user.ID); err != nil {
				return err
			}
			replaced = true
		}
		return q.CreateUserKey(ctx, db.CreateUserKeyParams{UserID: user.ID, ID: id, Version: st.Version,
			PayloadEncrypted: u.keys.Seal(atrest.UserKeysPayload, atrest.IDRow(user.ID), payload), Signature: signature})
	})
	switch {
	case errors.Is(err, errAlreadyStored):
		return false, nil
	case repository.IsUniqueViolation(err, "user_keys_id_key"):
		return false, conflict("a new user key needs a new id")
	}
	return replaced, err
}

// errAlreadyStored ends a transaction that found the request already done.
var errAlreadyStored = errors.New("already stored")

// UserKey returns U's statement and the wraps to it; ErrNotFound when none is published.
func (u *Unlock) UserKey(ctx context.Context, userID uuid.UUID) (atrest.UserKey, []db.UserKeyWrap, error) {
	uk, err := u.keys.UserKey(u.q.GetUserKey(ctx, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return uk, nil, ErrNotFound
	} else if err != nil {
		return uk, nil, err
	}
	wraps, err := u.q.ListUserKeyWraps(ctx, uk.ID)
	return uk, wraps, err
}

// PutUserKeyWrap stores the practice key or identity seed wrapped to the current U.
func (u *Unlock) PutUserKeyWrap(ctx context.Context, user atrest.User, in UserKeyWrapInput) error {
	if in.Kind != int(e2ee.KindPracticeKey) && in.Kind != int(e2ee.KindIdentitySeed) {
		return invalid("kind must be 1 (practice key) or 2 (identity seed)")
	}
	uk, err := u.keys.UserKey(u.q.GetUserKey(ctx, user.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return conflict("publish a user key before wrapping to it")
	} else if err != nil {
		return err
	}
	params, err := validateUserKeyWrap(user, uk, in, int(user.KeyVersion))
	if err != nil {
		return err
	}
	err = u.q.PutUserKeyWrap(ctx, params)
	if repository.IsForeignKeyViolation(err) {
		return conflict("the user key was replaced meanwhile; wrap to the new one")
	}
	return err
}

// validateUserKeyWrap checks a wrap to U as validateWrap does one to a device: kind
// and version bounds, the ephemeral point, the box size, and the identity key's
// signature over the wrap and the AAD rebuilt with U in the recipient's place.
func validateUserKeyWrap(user atrest.User, uk atrest.UserKey, in UserKeyWrapInput, maxVersion int) (db.PutUserKeyWrapParams, error) {
	if user.IdentityPublicKey == nil {
		return db.PutUserKeyWrapParams{}, conflict("set the identity key before sending signed wraps")
	}
	if in.UserKeyID != uk.ID {
		return db.PutUserKeyWrapParams{}, conflict("the user key was replaced; wrap to the current one")
	}
	if in.KeyVersion < 1 || in.KeyVersion > maxVersion {
		return db.PutUserKeyWrapParams{}, invalid("keyVersion must be between 1 and %d", maxVersion)
	}
	if !validPublicKey(in.EphemeralKey) {
		return db.PutUserKeyWrapParams{}, invalid("ephemeralKey must be a 65-byte uncompressed point on the glowie curve")
	}
	if len(in.Box) != e2ee.WrappedBoxSize {
		return db.PutUserKeyWrapParams{}, invalid("box must be %d bytes", e2ee.WrappedBoxSize)
	}
	pk, err := userKeyPublic(uk)
	if err != nil {
		return db.PutUserKeyWrapParams{}, err
	}
	aad := e2ee.WrapAAD(e2ee.UUID(user.ID), uint32(in.KeyVersion), e2ee.UUID(uk.ID), e2ee.WrapKind(in.Kind))
	if !e2ee.VerifyWrap(user.IdentityPublicKey, in.EphemeralKey, in.Box, aad, pk, in.Signature) {
		return db.PutUserKeyWrapParams{}, invalid("the wrap's signature does not verify against the identity key")
	}
	return db.PutUserKeyWrapParams{UserKeyID: uk.ID, Kind: int16(in.Kind), KeyVersion: int32(in.KeyVersion),
		EphemeralKey: in.EphemeralKey, Box: in.Box, Signature: in.Signature}, nil
}

// userKeyPublic reads U's public key from its stored statement, checked when stored.
func userKeyPublic(uk atrest.UserKey) ([]byte, error) {
	var st e2ee.UserKey
	if err := json.Unmarshal(uk.Payload, &st); err != nil {
		return nil, err
	}
	return st.PK, nil
}

// PutPasskeyBox stores U's scalar sealed under one of the account's passkeys, signed
// by the identity key over the AAD rebuilt here, so it opens only for that passkey,
// this account and the current U.
func (u *Unlock) PutPasskeyBox(ctx context.Context, user atrest.User, credentialID []byte, userKeyID uuid.UUID, box, signature []byte) error {
	if owned, err := u.q.CredentialOwned(ctx, db.CredentialOwnedParams{ID: credentialID, UserID: user.ID}); err != nil {
		return err
	} else if !owned {
		return ErrNotFound
	}
	if user.IdentityPublicKey == nil {
		return conflict("set the identity key before storing a passkey's box")
	}
	if len(box) != e2ee.WrappedBoxSize {
		return invalid("box must be %d bytes", e2ee.WrappedBoxSize)
	}
	uk, err := u.q.GetUserKey(ctx, user.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return conflict("publish a user key before sealing it to a passkey")
	} else if err != nil {
		return err
	}
	if userKeyID != uk.ID {
		return conflict("the user key was replaced; seal the current one")
	}
	aad := e2ee.PasskeyBoxAAD(e2ee.UUID(user.ID), e2ee.UUID(uk.ID), credentialID)
	if !e2ee.VerifyPasskeyBox(user.IdentityPublicKey, aad, box, signature) {
		return invalid("the box's signature does not verify against the identity key")
	}
	err = u.q.PutPasskeyBox(ctx, db.PutPasskeyBoxParams{CredentialID: credentialID, UserKeyID: uk.ID, Box: box, Signature: signature})
	if repository.IsForeignKeyViolation(err) {
		return conflict("the passkey was removed or the user key replaced meanwhile")
	}
	return err
}

// PasskeyUnlock is what a new phone fetches after signing in with a passkey.
type PasskeyUnlock struct {
	UserKey   atrest.UserKey
	Box       []byte
	Signature []byte
	Wraps     []db.UserKeyWrap
}

// PasskeyBox returns one passkey's box with U's statement and the wraps to U;
// ErrNotFound when the passkey is not the account's or has no box.
func (u *Unlock) PasskeyBox(ctx context.Context, userID uuid.UUID, credentialID []byte) (PasskeyUnlock, error) {
	box, err := u.q.GetPasskeyBox(ctx, db.GetPasskeyBoxParams{CredentialID: credentialID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return PasskeyUnlock{}, ErrNotFound
	} else if err != nil {
		return PasskeyUnlock{}, err
	}
	uk, wraps, err := u.UserKey(ctx, userID)
	if err != nil {
		return PasskeyUnlock{}, err
	}
	return PasskeyUnlock{UserKey: uk, Box: box.Box, Signature: box.Signature, Wraps: wraps}, nil
}

// DeletePasskeyBox stops a passkey from unlocking the keys; the passkey itself stays.
func (u *Unlock) DeletePasskeyBox(ctx context.Context, userID uuid.UUID, credentialID []byte) error {
	n, err := u.q.DeletePasskeyBox(ctx, db.DeletePasskeyBoxParams{CredentialID: credentialID, UserID: userID})
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}
