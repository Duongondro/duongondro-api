package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
)

type Devices struct {
	q *db.Queries
}

func NewDevices(pool *pgxpool.Pool) *Devices {
	return &Devices{q: db.New(pool)}
}

var tiers = map[string]bool{"hardware": true, "tee": true, "software": true}

func validPublicKey(key []byte) bool {
	_, err := e2ee.ParsePublicKey(key)
	return err == nil
}

// Register adds a device key; the same key again returns the existing device
// (created false). Nobody is refused over a software-tier key: the tier is
// information, not a gate.
func (d *Devices) Register(ctx context.Context, userID uuid.UUID, publicKey []byte, tier string) (db.Device, bool, error) {
	if !validPublicKey(publicKey) {
		return db.Device{}, false, invalid("publicKey must be a 65-byte uncompressed point on the glowie curve")
	}
	if !tiers[tier] {
		return db.Device{}, false, invalid("tier must be hardware, tee or software")
	}
	dev, err := d.q.CreateDevice(ctx, db.CreateDeviceParams{UserID: userID, PublicKey: publicKey, Tier: tier})
	if errors.Is(err, pgx.ErrNoRows) {
		dev, err = d.q.GetDeviceByKey(ctx, db.GetDeviceByKeyParams{UserID: userID, PublicKey: publicKey})
		return dev, false, err
	}
	return dev, err == nil, err
}

func (d *Devices) List(ctx context.Context, userID uuid.UUID) ([]db.Device, error) {
	return d.q.ListDevices(ctx, userID)
}

// Delete removes one of the user's devices; its wraps go with it.
func (d *Devices) Delete(ctx context.Context, userID, deviceID uuid.UUID) error {
	n, err := d.q.DeleteDevice(ctx, db.DeleteDeviceParams{ID: deviceID, UserID: userID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Owned returns one of the user's devices, or ErrNotFound.
func (d *Devices) Owned(ctx context.Context, userID, deviceID uuid.UUID) (db.Device, error) {
	dev, err := d.q.GetDevice(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && dev.UserID != userID) {
		return db.Device{}, ErrNotFound
	}
	return dev, err
}

func (d *Devices) DeviceList(ctx context.Context, userID uuid.UUID) (db.DeviceList, error) {
	list, err := d.q.GetDeviceList(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return list, ErrNotFound
	}
	return list, err
}

// PutDeviceList stores a new signed device list. The server checks what it can
// without trusting the client: the signature by the user's identity key over the
// exact bytes, that the payload is the canonical form (so every verifier hashes the
// same bytes), that it names this user, that every listed device is registered to
// them with that key and tier, and that the version goes up. A stolen session can
// register a device but cannot get it into a list, since it has no identity key.
func (d *Devices) PutDeviceList(ctx context.Context, user db.User, payload, signature []byte) error {
	if user.IdentityPublicKey == nil {
		return conflict("set the identity key before publishing a device list")
	}
	if !e2ee.VerifyStatement(user.IdentityPublicKey, e2ee.TypeDeviceList, payload, signature) {
		return invalid("the signature does not verify against the identity key")
	}
	var list e2ee.DeviceList
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return invalid("payload is not a device list: %v", err)
	}
	if canonical, err := e2ee.Marshal(list); err != nil || !bytes.Equal(canonical, payload) {
		return invalid("payload is not in canonical form (compact JSON, keys in order)")
	}
	if list.User != user.ID.String() {
		return invalid("the device list names another user")
	}
	if list.Version < 1 || list.IssuedAt <= 0 || len(list.Devices) == 0 {
		return invalid("version, issuedAt and at least one device are required")
	}
	registered, err := d.q.ListDevices(ctx, user.ID)
	if err != nil {
		return err
	}
	byID := map[string]db.Device{}
	for _, dev := range registered {
		byID[dev.ID.String()] = dev
	}
	seen := map[string]bool{}
	for _, item := range list.Devices {
		dev, ok := byID[item.ID]
		if !ok || seen[item.ID] {
			return invalid("device %s is not registered to this user, or is listed twice", item.ID)
		}
		seen[item.ID] = true
		if !bytes.Equal(dev.PublicKey, item.PK) || dev.Tier != item.Tier {
			return invalid("device %s is listed with a key or tier other than its registered one", item.ID)
		}
	}
	n, err := d.q.PutDeviceList(ctx, db.PutDeviceListParams{UserID: user.ID, Version: list.Version, Payload: payload, Signature: signature})
	if err != nil {
		return fmt.Errorf("put device list: %w", err)
	}
	if n == 0 {
		return conflict("version %d is not above the stored device list's", list.Version)
	}
	return nil
}
