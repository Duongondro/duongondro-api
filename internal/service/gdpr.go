package service

import (
	"context"
	"errors"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

// GDPR serves "all of my data" (Articles 15 and 20) and "delete everything"
// (Article 17), both self-service (design: Data export and deletion).
type GDPR struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

func NewGDPR(pool *pgxpool.Pool) *GDPR { return &GDPR{pool: pool, q: db.New(pool)} }

// Export is exactly what the server stores about one user, sealed blobs and all.
// The phone decrypts the sealed sessions itself and merges them in, so the ZIP it
// builds holds counts the server never saw. Every table appears under its own name
// (TestExportCoversEveryTable keeps it that way); session tokens appear only as
// their creation times, since the server holds no more than a hash of them.
type Export struct {
	ExportedAt         time.Time               `json:"exportedAt"`
	Users              db.User                 `json:"users"`
	Sessions           []time.Time             `json:"sessions"`
	Devices            []db.Device             `json:"devices"`
	DeviceLists        *db.DeviceList          `json:"device_lists"`
	KeyWraps           []db.KeyWrap            `json:"key_wraps"`
	PracticeLogs       []db.PracticeLog        `json:"practice_logs"`
	RecoveryBoxes      []db.RecoveryBox        `json:"recovery_boxes"`
	InviteTree         *db.ExportInviteNodeRow `json:"invite_tree"`
	Invites            []db.Invite             `json:"invites"`
	InviteRedemptions  []db.InviteRedemption   `json:"invite_redemptions"`
	Friendships        []db.ListFriendsRow     `json:"friendships"`
	Blocks             []db.Block              `json:"blocks"`
	Reports            []db.ExportReportsRow   `json:"reports"`
	Streaks            []db.Streak             `json:"streaks"`
	DatabaseGeneration string                  `json:"database_generation"`
}

// ExportedTables names every table Export covers. database_generation holds no
// personal data; it is listed because the cursor in the apps refers to it.
var ExportedTables = []string{
	"blocks", "database_generation", "device_lists", "devices", "friendships", "invite_redemptions",
	"invite_tree", "invites", "key_wraps", "practice_logs", "recovery_boxes", "reports",
	"sessions", "streaks", "users",
}

// Export reads everything in one snapshot.
func (g *GDPR) Export(ctx context.Context, userID uuid.UUID) (Export, error) {
	var out Export
	err := pgx.BeginTxFunc(ctx, g.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		q := g.q.WithTx(tx)
		var err error
		out.ExportedAt = time.Now().UTC()
		if out.Users, err = q.GetUser(ctx, userID); err != nil {
			return err
		}
		if out.Sessions, err = q.ExportSessions(ctx, userID); err != nil {
			return err
		}
		if out.Devices, err = q.ListDevices(ctx, userID); err != nil {
			return err
		}
		if list, err := q.GetDeviceList(ctx, userID); err == nil {
			out.DeviceLists = &list
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if out.KeyWraps, err = q.ExportWraps(ctx, userID); err != nil {
			return err
		}
		if out.PracticeLogs, err = q.ExportLogs(ctx, userID); err != nil {
			return err
		}
		if out.RecoveryBoxes, err = q.ListRecoveryBoxes(ctx, userID); err != nil {
			return err
		}
		if node, err := q.ExportInviteNode(ctx, &userID); err == nil {
			out.InviteTree = &node
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if out.Invites, err = q.ListInvites(ctx, userID); err != nil {
			return err
		}
		if out.InviteRedemptions, err = q.ExportRedemptions(ctx, userID); err != nil {
			return err
		}
		if out.Friendships, err = q.ListFriends(ctx, userID); err != nil {
			return err
		}
		if out.Blocks, err = q.ListBlocks(ctx, userID); err != nil {
			return err
		}
		if out.Reports, err = q.ExportReports(ctx, userID); err != nil {
			return err
		}
		if out.Streaks, err = q.OwnStreaks(ctx, userID); err != nil {
			return err
		}
		state, err := q.SyncState(ctx)
		if err != nil {
			return err
		}
		out.DatabaseGeneration = state.Generation.String()
		return nil
	})
	return out, err
}

// Purge deletes every row belonging to the user in one transaction: account,
// sessions, devices and wraps, device list, sealed logs, recovery boxes, invites and
// redemptions, friendships both ways, blocks both ways, reports filed by and about
// them, and streak statements, all through ON DELETE CASCADE. Their node in the
// invite tree stays, anonymous, so others' "invited by" stays consistent. Friends'
// phones drop the person on their next sync, since the friend list no longer has
// them.
func (g *GDPR) Purge(ctx context.Context, userID uuid.UUID) error {
	n, err := g.q.DeleteUser(ctx, userID)
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}
