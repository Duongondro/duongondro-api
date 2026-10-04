package service

import (
	"context"
	"encoding/json"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
	repo    *repository.Wraps
	devices *Devices
}

func NewWraps(pool *pgxpool.Pool, devices *Devices) *Wraps {
	return &Wraps{q: db.New(pool), repo: repository.NewWraps(pool), devices: devices}
}

// Put stores a wrap to one of the user's devices. What the server cannot verify is
// limited to where the design needs it (design: Keys): an enrolment tag only for a
// device that has no wraps yet (its first, from the QR secret), a self tag never over
// a signed wrap. So a session alone cannot swap a verifiable wrap for a blob.
func (w *Wraps) Put(ctx context.Context, user db.User, deviceID uuid.UUID, in WrapInput) error {
	dev, err := w.devices.Owned(ctx, user.ID, deviceID)
	if err != nil {
		return err
	}
	if err := validateWrap(user, dev, in, int(user.KeyVersion)); err != nil {
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
func (w *Wraps) Rotate(ctx context.Context, user db.User, newVersion int, wraps []RotationWrap) error {
	if user.IdentityPublicKey == nil {
		return conflict("set the identity key before rotating the practice key")
	}
	return w.repo.Rotate(ctx, user.ID, newVersion, func(locked db.User, holders []db.PracticeKeyHoldersRow) ([]db.PutWrapParams, error) {
		if newVersion != int(locked.KeyVersion)+1 {
			return nil, conflict("newVersion must be %d", locked.KeyVersion+1)
		}
		// Only devices in the signed device list count: one a session registered and
		// gave an unsigned wrap is not the user's, and must not block their rotation.
		listed, err := w.listedDevices(ctx, locked)
		if err != nil {
			return nil, err
		}
		pending := map[uuid.UUID]db.PracticeKeyHoldersRow{}
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
			dev := db.Device{ID: h.ID, PublicKey: h.PublicKey}
			if err := validateWrap(locked, dev, rw.WrapInput, newVersion); err != nil {
				return nil, err
			}
			params = append(params, wrapParams(h.ID, rw.WrapInput))
		}
		if len(pending) > 0 {
			return nil, invalid("a rotation must wrap the new key to every device holding the current one (%d missing)", len(pending))
		}
		return params, nil
	})
}

// listedDevices returns the device ids in the user's signed device list, or nil when
// none has been published yet.
func (w *Wraps) listedDevices(ctx context.Context, user db.User) (map[string]bool, error) {
	stored, err := w.q.GetDeviceList(ctx, user.ID)
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
func validateWrap(user db.User, dev db.Device, in WrapInput, maxVersion int) error {
	if in.Kind != int(e2ee.KindPracticeKey) && in.Kind != int(e2ee.KindIdentitySeed) {
		return invalid("kind must be 1 (practice key) or 2 (identity seed)")
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
