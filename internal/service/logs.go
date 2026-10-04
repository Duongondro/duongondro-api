package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/repository"
)

// Sealed log sizes (docs/crypto.md, Sealed session): nonce ‖ ciphertext ‖ tag over a
// body padded to a multiple of 256 bytes, at most 16 KiB of it.
const (
	sealedOverhead = e2ee.NonceSize + 16
	padBlock       = 256
	maxPadded      = 16 << 10
)

type LogInput struct {
	Sealed     []byte
	KeyVersion int
	UpdatedAt  time.Time
	Deleted    bool
}

type Logs struct {
	q    *db.Queries
	sync *repository.Sync
	now  func() time.Time
}

func NewLogs(pool *pgxpool.Pool) *Logs {
	return &Logs{q: db.New(pool), sync: repository.NewSync(pool), now: time.Now}
}

// Put stores a sealed log, or its deletion, if it is newer by the client's clock than
// the stored one, and returns the stored row either way. A deletion keeps a tombstone
// without content.
func (l *Logs) Put(ctx context.Context, user db.User, id uuid.UUID, in LogInput) (db.PracticeLog, error) {
	if !isV7(id) {
		return db.PracticeLog{}, invalid("the log id must be a UUIDv7")
	}
	if in.UpdatedAt.IsZero() || in.UpdatedAt.After(l.now().Add(24*time.Hour)) {
		return db.PracticeLog{}, invalid("updatedAt must be set and not more than a day ahead")
	}
	current := int(user.KeyVersion)
	params := db.UpsertLogParams{ID: id, UserID: user.ID, ClientUpdatedAt: in.UpdatedAt}
	if in.Deleted {
		if in.Sealed != nil {
			return db.PracticeLog{}, invalid("a deletion carries no sealed content")
		}
		// No content, so no key: the tombstone takes the current version.
		params.KeyVersion = int32(current)
		at := in.UpdatedAt
		params.DeletedAt = &at
	} else {
		n := len(in.Sealed)
		if n < sealedOverhead+padBlock || n > sealedOverhead+maxPadded || (n-sealedOverhead)%padBlock != 0 {
			return db.PracticeLog{}, invalid("sealed must be nonce, ciphertext and tag over a body padded to a multiple of %d bytes, at most %d", padBlock, maxPadded)
		}
		if in.KeyVersion > current || in.KeyVersion < 1 {
			return db.PracticeLog{}, invalid("keyVersion must be between 1 and %d", current)
		}
		if in.KeyVersion < current {
			return db.PracticeLog{}, &OldKeyError{Current: current}
		}
		params.Sealed = in.Sealed
		params.KeyVersion = int32(in.KeyVersion)
	}
	row, err := l.q.UpsertLog(ctx, params)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not newer, or another user's id: answer with the stored row, or 404.
		row, err = l.q.GetLog(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && row.UserID != user.ID) {
			return db.PracticeLog{}, ErrNotFound
		}
	}
	return row, err
}

// Sync returns the logs changed since the cursor string ("" for all).
func (l *Logs) Sync(ctx context.Context, userID uuid.UUID, since string) (repository.Changes, error) {
	var cursor *repository.Cursor
	if since != "" {
		c, ok := ParseCursor(since)
		if !ok {
			return repository.Changes{}, invalid("malformed cursor")
		}
		cursor = &c
	}
	return l.sync.Since(ctx, userID, cursor)
}

func FormatCursor(c repository.Cursor) string {
	return c.Generation.String() + ":" + strconv.FormatUint(c.Xid, 10)
}

func ParseCursor(s string) (repository.Cursor, bool) {
	gen, xid, ok := strings.Cut(s, ":")
	if !ok {
		return repository.Cursor{}, false
	}
	g, err := uuid.Parse(gen)
	if err != nil {
		return repository.Cursor{}, false
	}
	x, err := strconv.ParseUint(xid, 10, 64)
	if err != nil {
		return repository.Cursor{}, false
	}
	return repository.Cursor{Generation: g, Xid: x}, true
}

// isV7 reports a version-7, RFC 9562 variant UUID: clients generate log ids with it.
func isV7(id uuid.UUID) bool {
	return id[6]>>4 == 7 && id[8]&0xc0 == 0x80
}
