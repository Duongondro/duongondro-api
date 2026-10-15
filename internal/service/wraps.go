package service

import (
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

// WrapInput is a secret wrapped to one device (docs/crypto.md, Wraps).
type WrapInput struct {
	Kind          int
	KeyVersion    int
	EphemeralKey  []byte
	Box           []byte
	AuthType      string
	Authenticator []byte
}

type Wraps struct {
	q       *db.Queries
	keys    *atrest.Keys
	repo    *repository.Wraps
	devices *Devices
}

func NewWraps(pool *pgxpool.Pool, keys *atrest.Keys, devices *Devices) *Wraps {
	return &Wraps{q: db.New(pool), keys: keys, repo: repository.NewWraps(pool, keys), devices: devices}
}

// Put stores a wrap to one of the user's devices. What the server cannot verify is
// limited to where the design needs it (design: Keys): an enrolment tag only for a
// device that has no wraps yet (its first, from the QR secret), a self tag never over
// a signed wrap. So a session alone cannot swap a verifiable wrap for a blob.
func (w *Wraps) Put(ctx context.Context, user atrest.User, deviceID uuid.UUID, in WrapInput) error {
	dev, err := w.devices.Owned(ctx, user.ID, deviceID)
	if err != nil {
		return err
	}
	maxVersion := int(user.KeyVersion)
	if in.Kind == int(e2ee.KindUserKey) {
		// U's scalar goes from phone to phone signed, at U's own version.
		uk, err := w.q.GetUserKey(ctx, user.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return conflict("publish a user key before wrapping it to a device")
		} else if err != nil {
			return err
		}
		if in.AuthType != "signature" {
			return invalid("a user key's wrap is signed by the identity key")
		}
		if in.KeyVersion != int(uk.Version) {
			return conflict("a user key's wrap carries its version, %d", uk.Version)
		}
		maxVersion = int(uk.Version)
	}
	if err := validateWrap(user, dev, in, maxVersion); err != nil {
		return err
	}
	if in.AuthType != "signature" {
		existing, err := w.q.ListWraps(ctx, dev.ID)
		if err != nil {
			return err
		}
		for _, e := range existing {
			if in.AuthType == "enrol" {
				return conflict("an enrolment wrap is only for a device without wraps; sign it with the identity key")
			}
			if e.Kind == int16(in.Kind) && e.KeyVersion == int32(in.KeyVersion) && e.AuthType == "signature" {
				return conflict("a signed wrap is never replaced by an unsigned one")
			}
		}
	}
	return w.q.PutWrap(ctx, wrapParams(dev.ID, in))
}

func (w *Wraps) List(ctx context.Context, userID, deviceID uuid.UUID) ([]db.KeyWrap, error) {
	if _, err := w.devices.Owned(ctx, userID, deviceID); err != nil {
		return nil, err
	}
	return w.q.ListWraps(ctx, deviceID)
}

// RotationWrap is one wrap of the new practice key in a rotation.
type RotationWrap struct {
	DeviceID uuid.UUID
	WrapInput
}

// Rotate moves the practice key to newVersion. The wraps must carry it to exactly the
// devices holding the current version, each once, all of kind 1 at newVersion: a
// device left out would lose the practice key.
//
// While the user key U holds the current version, the new key is wrapped to it too
// (toUserKey), or a passkey could no longer unlock the counts.
func (w *Wraps) Rotate(ctx context.Context, user atrest.User, newVersion int, wraps []RotationWrap, toUserKey *UserKeyWrapInput) error {
	if user.IdentityPublicKey == nil {
		return conflict("set the identity key before rotating the practice key")
	}
	return w.repo.Rotate(ctx, user.ID, newVersion, func(locked atrest.User, holders []atrest.Device, uk *repository.UserKeyHolder) ([]db.PutWrapParams, *db.PutUserKeyWrapParams, error) {
		if newVersion != int(locked.KeyVersion)+1 {
			return nil, nil, conflict("newVersion must be %d", locked.KeyVersion+1)
		}
		var ukParams *db.PutUserKeyWrapParams
		switch {
		case toUserKey != nil && uk == nil:
			return nil, nil, conflict("there is no user key to wrap to")
		case toUserKey != nil:
			if toUserKey.Kind != int(e2ee.KindPracticeKey) || toUserKey.KeyVersion != newVersion {
				return nil, nil, invalid("a rotation wraps the practice key (kind 1) at version %d", newVersion)
			}
			p, err := validateUserKeyWrap(locked, uk.UserKey, *toUserKey, newVersion)
			if err != nil {
				return nil, nil, err
			}
			ukParams = &p
		case uk != nil && uk.HoldsCurrent:
			return nil, nil, invalid("a rotation must wrap the new key to the user key, which holds the current one")
		}
		params, err := w.rotationWraps(ctx, locked, holders, newVersion, wraps)
		return params, ukParams, err
	})
}

// rotationWraps checks a rotation's device wraps against the devices holding the
// current practice key.
func (w *Wraps) rotationWraps(ctx context.Context, locked atrest.User, holders []atrest.Device, newVersion int, wraps []RotationWrap) ([]db.PutWrapParams, error) {
	// Only devices in the signed device list count: one a session registered and
	// gave an unsigned wrap is not the user's, and must not block their rotation.
	listed, err := w.listedDevices(ctx, locked)
	if err != nil {
		return nil, err
	}
	pending := map[uuid.UUID]atrest.Device{}
	for _, h := range holders {
		if listed == nil || listed[h.ID.String()] {
			pending[h.ID] = h
		}
	}
	params := make([]db.PutWrapParams, 0, len(wraps))
	for _, rw := range wraps {
		h, ok := pending[rw.DeviceID]
		if !ok {
			return nil, invalid("device %s does not hold the current practice key, or is wrapped to twice", rw.DeviceID)
		}
		delete(pending, rw.DeviceID)
		if rw.Kind != int(e2ee.KindPracticeKey) || rw.KeyVersion != newVersion {
			return nil, invalid("a rotation wraps the practice key (kind 1) at version %d", newVersion)
		}
		// The server can verify a signature only; a rotation from a session
		// without the identity key would lock every device out.
		if rw.AuthType != "signature" {
			return nil, invalid("rotation wraps are signed by the identity key")
		}
		if err := validateWrap(locked, h, rw.WrapInput, newVersion); err != nil {
			return nil, err
		}
		params = append(params, wrapParams(h.ID, rw.WrapInput))
	}
	if len(pending) > 0 {
		return nil, invalid("a rotation must wrap the new key to every device holding the current one (%d missing)", len(pending))
	}
	return params, nil
}

// listedDevices returns the device ids in the user's signed device list, or nil when
// none has been published yet.
func (w *Wraps) listedDevices(ctx context.Context, user atrest.User) (map[string]bool, error) {
	stored, err := w.keys.DeviceList(w.q.GetDeviceList(ctx, user.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var list e2ee.DeviceList
	if err := json.Unmarshal(stored.Payload, &list); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range list.Devices {
		out[d.ID] = true
	}
	return out, nil
}

// validateWrap checks what the server can: kind and version, the ephemeral key on
// the glowie curve, the box size, and the authenticator. A signature is verified
// against the identity key over the wrap and the AAD rebuilt here, so a wrap cannot
// be moved to another device, user, kind or version; HMAC tags only the devices
// can check, so their size is all the server sees.
func validateWrap(user atrest.User, dev atrest.Device, in WrapInput, maxVersion int) error {
	if in.Kind != int(e2ee.KindPracticeKey) && in.Kind != int(e2ee.KindIdentitySeed) && in.Kind != int(e2ee.KindUserKey) {
		return invalid("kind must be 1 (practice key), 2 (identity seed) or 4 (user key)")
	}
	if in.KeyVersion < 1 || in.KeyVersion > maxVersion {
		return invalid("keyVersion must be between 1 and %d", maxVersion)
	}
	if !validPublicKey(in.EphemeralKey) {
		return invalid("ephemeralKey must be a 65-byte uncompressed point on the glowie curve")
	}
	if len(in.Box) != e2ee.WrappedBoxSize {
		return invalid("box must be %d bytes", e2ee.WrappedBoxSize)
	}
	switch in.AuthType {
	case "signature":
		if user.IdentityPublicKey == nil {
			return conflict("set the identity key before sending signed wraps")
		}
		aad := e2ee.WrapAAD(e2ee.UUID(user.ID), uint32(in.KeyVersion), e2ee.UUID(dev.ID), e2ee.WrapKind(in.Kind))
		if !e2ee.VerifyWrap(user.IdentityPublicKey, in.EphemeralKey, in.Box, aad, dev.PublicKey, in.Authenticator) {
			return invalid("the wrap's signature does not verify against the identity key")
		}
	case "enrol", "self":
		if len(in.Authenticator) != 32 {
			return invalid("an HMAC authenticator is 32 bytes")
		}
	default:
		return invalid("authType must be signature, enrol or self")
	}
	return nil
}

func wrapParams(deviceID uuid.UUID, in WrapInput) db.PutWrapParams {
	return db.PutWrapParams{
		DeviceID: deviceID, Kind: int16(in.Kind), KeyVersion: int32(in.KeyVersion),
		EphemeralKey: in.EphemeralKey, Box: in.Box, AuthType: in.AuthType, Authenticator: in.Authenticator,
	}
}
