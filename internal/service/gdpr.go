package service

import (
	"context"
	"crypto/sha256"
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
	ExportedAt         time.Time                    `json:"exportedAt"`
	AdmissionCodes     []db.ExportAdmissionCodesRow `json:"admission_codes"`
	Users              db.User                      `json:"users"`
	Sessions           []time.Time                  `json:"sessions"`
	Devices            []db.Device                  `json:"devices"`
	DeviceLists        *db.DeviceList               `json:"device_lists"`
	KeyWraps           []db.KeyWrap                 `json:"key_wraps"`
	PracticeLogs       []db.PracticeLog             `json:"practice_logs"`
	RecoveryBoxes      []db.RecoveryBox             `json:"recovery_boxes"`
	InviteTree         *db.ExportInviteNodeRow      `json:"invite_tree"`
	Invites            []db.Invite                  `json:"invites"`
	InviteRedemptions  []db.InviteRedemption        `json:"invite_redemptions"`
	Friendships        []db.ListFriendsRow          `json:"friendships"`
	Blocks             []db.Block                   `json:"blocks"`
	Reports            []db.ExportReportsRow        `json:"reports"`
	Streaks            []db.Streak                  `json:"streaks"`
	Credentials        []db.ExportCredentialsRow    `json:"credentials"`
	AuthIdentities     []db.ExportIdentitiesRow     `json:"auth_identities"`
	MagicLinks         []db.ExportMagicLinksRow     `json:"magic_links"`
	WebauthnSessions   []string                     `json:"webauthn_sessions"`
	PushTokens         []db.ExportPushTokensRow     `json:"push_tokens"`
	Nudges             []db.Nudge                   `json:"nudges"`
	AuthNonces         []string                     `json:"auth_nonces"`
	PurgeLog           []string                     `json:"purge_log"`
	DatabaseGeneration string                       `json:"database_generation"`
}

// ExportedTables names every table Export covers. database_generation holds no
// personal data; it is listed because the cursor in the apps refers to it.
// webauthn_sessions are passkey ceremonies of the last five minutes: listed as
// always empty, since one in flight is no stored data, and deleted by a purge.
// auth_nonces are tied to nobody, and purge_log holds only hashes of purged ids:
// both are listed as always empty.
// admission_codes lists the code the account was admitted with, if any, without
// the code's hash.
// friendships lists friends as GET /api/friends does, with their display names and
// genders: third-party data, but no more than the account already sees.
// Passkeys, identities and push tokens appear without their secrets (the public key,
// Apple's refresh token and the device token stay out).
var ExportedTables = []string{
	"admission_codes", "auth_identities", "auth_nonces", "blocks", "credentials", "database_generation", "device_lists",
	"devices", "friendships", "invite_redemptions", "invite_tree", "invites", "key_wraps",
	"magic_links", "nudges", "practice_logs", "purge_log", "push_tokens", "recovery_boxes", "reports",
	"sessions", "streaks", "users", "webauthn_sessions",
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
		if out.AdmissionCodes, err = q.ExportAdmissionCodes(ctx, &userID); err != nil {
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
		if out.Credentials, err = q.ExportCredentials(ctx, userID); err != nil {
			return err
		}
		if out.AuthIdentities, err = q.ExportIdentities(ctx, userID); err != nil {
			return err
		}
		if out.MagicLinks, err = q.ExportMagicLinks(ctx, userID); err != nil {
			return err
		}
		out.WebauthnSessions, out.AuthNonces, out.PurgeLog = []string{}, []string{}, []string{}
		if out.PushTokens, err = q.ExportPushTokens(ctx, userID); err != nil {
			return err
		}
		if out.Nudges, err = q.ExportNudges(ctx, userID); err != nil {
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
// them, and streak statements, all through ON DELETE CASCADE; an admission code the
// account used stays spent, without the link to it (ON DELETE SET NULL). Their node in the
// invite tree stays, anonymous, so others' "invited by" stays consistent. Friends'
// phones drop the person on their next sync, since the friend list no longer has
// them.
//
// Unused magic links to the user's addresses and passkey ceremonies in flight go
// too; they are not tied to the account by a foreign key. Revoking Sign in with
// Apple (SignIn.RevokeApple) comes first, while the refresh tokens still exist.
func (g *GDPR) Purge(ctx context.Context, userID uuid.UUID) error {
	return pgx.BeginTxFunc(ctx, g.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := g.q.WithTx(tx)
		if err := q.DeleteMagicLinksForUser(ctx, userID); err != nil {
			return err
		}
		if err := q.DeleteWebauthnSessionsForUser(ctx, &userID); err != nil {
			return err
		}
		// Only a hash of the id, to delete the account again if a backup that predates
		// the purge is ever restored (ReapplyPurges).
		sum := sha256.Sum256(userID[:])
		if err := q.RecordPurge(ctx, sum[:]); err != nil {
			return err
		}
		n, err := q.DeleteUser(ctx, userID)
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return err
	})
}

// ReapplyPurges deletes again every account purged after the backup the database was
// restored from (design: Data export and deletion › Backups). Run it after a restore,
// with `duongondro-api reapply-purges`.
func (g *GDPR) ReapplyPurges(ctx context.Context) (int64, error) {
	return g.q.ReapplyPurges(ctx)
}
