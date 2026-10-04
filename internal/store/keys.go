package store

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Device is a registered device key.
type Device struct {
	ID        string
	UserID    string
	PublicKey []byte
	Tier      string
	CreatedAt time.Time
}

// RegisterDevice stores a device key for userID and binds the session with
// sessionHash to it. created is false when the same id, key and tier were
// already registered to the user; any other clash is ErrConflict.
func (s *Store) RegisterDevice(ctx context.Context, userID string, sessionHash []byte, d Device) (out Device, created bool, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO devices (id, user_id, public_key, tier) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
			RETURNING id::text, user_id::text, public_key, tier, created_at`, d.ID, userID, d.PublicKey, d.Tier).
			Scan(&out.ID, &out.UserID, &out.PublicKey, &out.Tier, &out.CreatedAt)
		created = err == nil
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT id::text, user_id::text, public_key, tier, created_at FROM devices WHERE id = $1`, d.ID).
				Scan(&out.ID, &out.UserID, &out.PublicKey, &out.Tier, &out.CreatedAt)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && (out.UserID != userID || !bytes.Equal(out.PublicKey, d.PublicKey) || out.Tier != d.Tier) {
				return ErrConflict
			}
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET device_id = $1 WHERE token_hash = $2 AND user_id = $3`, d.ID, sessionHash, userID)
		return err
	})
	return out, created, err
}

// ListDevices returns the user's devices, oldest first.
func (s *Store) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, user_id::text, public_key, tier, created_at
		FROM devices WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Device, error) {
		var d Device
		err := r.Scan(&d.ID, &d.UserID, &d.PublicKey, &d.Tier, &d.CreatedAt)
		return d, err
	})
}

// DeleteDevice removes one of the user's devices; its wraps, push token and
// sessions go with it (foreign keys).
func (s *Store) DeleteDevice(ctx context.Context, userID, deviceID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1 AND user_id = $2`, deviceID, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ListedDevice is one entry of a parsed device-list payload.
type ListedDevice struct {
	ID        string
	PublicKey []byte
	Tier      string
}

// DeviceList is a stored signed device-list statement.
type DeviceList struct {
	UserID     string
	Version    int64
	Payload    []byte
	Signature  []byte
	IdentityPK []byte
}

// ErrUnknownDevice means a listed device is not registered to the user with
// that key and tier.
var ErrUnknownDevice = errors.New("store: unknown device")

// PublishDeviceList stores l if its version is higher than the stored one.
// On ErrStale, current is the stored version.
func (s *Store) PublishDeviceList(ctx context.Context, l DeviceList, devices []ListedDevice) (current int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		for _, d := range devices {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices
				WHERE id = $1 AND user_id = $2 AND public_key = $3 AND tier = $4)`,
				d.ID, l.UserID, d.PublicKey, d.Tier).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return ErrUnknownDevice
			}
		}
		err := tx.QueryRow(ctx, `INSERT INTO device_lists (user_id, version, payload, signature, identity_pk)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (user_id) DO UPDATE SET version = EXCLUDED.version, payload = EXCLUDED.payload,
				signature = EXCLUDED.signature, identity_pk = EXCLUDED.identity_pk, updated_at = now()
			WHERE device_lists.version < EXCLUDED.version
			RETURNING version`, l.UserID, l.Version, l.Payload, l.Signature, l.IdentityPK).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := tx.QueryRow(ctx, `SELECT version FROM device_lists WHERE user_id = $1`, l.UserID).Scan(&current); err != nil {
				return err
			}
			return ErrStale
		}
		return err
	})
	return current, err
}

// GetDeviceList returns owner's newest list if viewer is the owner or a
// friend with no block either way; otherwise ErrNotFound.
func (s *Store) GetDeviceList(ctx context.Context, viewer, owner string) (DeviceList, error) {
	var l DeviceList
	if viewer != owner {
		ok, err := s.connected(ctx, s.pool, viewer, owner)
		if err != nil {
			return l, err
		}
		if !ok {
			return l, ErrNotFound
		}
	}
	err := s.pool.QueryRow(ctx, `SELECT user_id::text, version, payload, signature, identity_pk
		FROM device_lists WHERE user_id = $1`, owner).
		Scan(&l.UserID, &l.Version, &l.Payload, &l.Signature, &l.IdentityPK)
	return l, notFound(err)
}

// connected reports whether a and b are friends and neither blocked the
// other.
func (s *Store) connected(ctx context.Context, q querier, a, b string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM friendships
			WHERE user_a = LEAST($1::uuid, $2::uuid) AND user_b = GREATEST($1::uuid, $2::uuid))
		AND NOT EXISTS (SELECT 1 FROM blocks
			WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1))`, a, b).Scan(&ok)
	return ok, err
}

// Connected is connected for callers outside a transaction.
func (s *Store) Connected(ctx context.Context, a, b string) (bool, error) {
	return s.connected(ctx, s.pool, a, b)
}

// Wrap is a stored key wrap.
type Wrap struct {
	UserID            string
	KeyVersion        int32
	RecipientDevice   string
	Kind              int16
	SenderID          string
	EPK               []byte
	Box               []byte
	AuthenticatorKind string
	Authenticator     []byte
	CreatedAt         time.Time
}

// DevicePublicKey returns the key of a device registered to userID.
func (s *Store) DevicePublicKey(ctx context.Context, userID, deviceID string) ([]byte, error) {
	var pk []byte
	err := s.pool.QueryRow(ctx, `SELECT public_key FROM devices WHERE id = $1 AND user_id = $2`, deviceID, userID).Scan(&pk)
	return pk, notFound(err)
}

// PutWrap stores w, replacing a wrap with the same AAD fields and sender.
// ErrUnknownDevice if the recipient device is not the user's.
func (s *Store) PutWrap(ctx context.Context, w Wrap) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO wraps (user_id, key_version, recipient_device, kind, sender_id,
			epk, box, authenticator_kind, authenticator)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (user_id, recipient_device, kind, key_version, sender_id) DO UPDATE SET
			epk = EXCLUDED.epk, box = EXCLUDED.box, authenticator_kind = EXCLUDED.authenticator_kind,
			authenticator = EXCLUDED.authenticator, created_at = now()`,
		w.UserID, w.KeyVersion, w.RecipientDevice, w.Kind, w.SenderID, w.EPK, w.Box, w.AuthenticatorKind, w.Authenticator)
	if isFK(err) {
		return ErrUnknownDevice
	}
	return err
}

// ListWraps returns wraps addressed to one of userID's devices, optionally
// of one kind. ErrNotFound if the device is not the user's.
func (s *Store) ListWraps(ctx context.Context, userID, deviceID string, kind int16) ([]Wrap, error) {
	if _, err := s.DevicePublicKey(ctx, userID, deviceID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT user_id::text, key_version, recipient_device::text, kind, sender_id::text,
			epk, box, authenticator_kind, authenticator, created_at
		FROM wraps WHERE user_id = $1 AND recipient_device = $2 AND ($3 = 0 OR kind = $3)
		ORDER BY key_version, kind, created_at`, userID, deviceID, kind)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Wrap, error) {
		var w Wrap
		err := r.Scan(&w.UserID, &w.KeyVersion, &w.RecipientDevice, &w.Kind, &w.SenderID,
			&w.EPK, &w.Box, &w.AuthenticatorKind, &w.Authenticator, &w.CreatedAt)
		return w, err
	})
}

// RecoveryBox is one sealed secret for the recovery code.
type RecoveryBox struct {
	Kind      int16
	Box       []byte
	UpdatedAt time.Time
}

// PutRecoveryBox stores or replaces the user's box of one kind.
func (s *Store) PutRecoveryBox(ctx context.Context, userID string, kind int16, box []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO recovery_boxes (user_id, kind, box) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, kind) DO UPDATE SET box = EXCLUDED.box, updated_at = now()`, userID, kind, box)
	return err
}

// ListRecoveryBoxes returns the user's boxes.
func (s *Store) ListRecoveryBoxes(ctx context.Context, userID string) ([]RecoveryBox, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, box, updated_at FROM recovery_boxes WHERE user_id = $1 ORDER BY kind`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RecoveryBox, error) {
		var b RecoveryBox
		err := r.Scan(&b.Kind, &b.Box, &b.UpdatedAt)
		return b, err
	})
}

// SetKeyVersion advances the practice key version by exactly one. On
// ErrStale, current is the stored version.
func (s *Store) SetKeyVersion(ctx context.Context, userID string, next int32) (current int32, err error) {
	err = s.pool.QueryRow(ctx, `UPDATE users SET key_version = $2 WHERE id = $1 AND key_version = $2 - 1
		RETURNING key_version`, userID, next).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := s.pool.QueryRow(ctx, `SELECT key_version FROM users WHERE id = $1`, userID).Scan(&current); err != nil {
			return 0, err
		}
		return current, ErrStale
	}
	return current, err
}

// Befriend records a friendship (idempotent).
func (s *Store) Befriend(ctx context.Context, a, b string) error {
	return befriend(ctx, s.pool, a, b)
}

func befriend(ctx context.Context, q querier, a, b string) error {
	_, err := q.Exec(ctx, `INSERT INTO friendships (user_a, user_b)
		VALUES (LEAST($1::uuid, $2::uuid), GREATEST($1::uuid, $2::uuid)) ON CONFLICT DO NOTHING`, a, b)
	return err
}
