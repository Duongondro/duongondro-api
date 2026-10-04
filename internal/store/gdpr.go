package store

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/ids"
)

// exportTable says which rows of a table are the caller's and which
// columns are left out (secrets that are not data about the person).
type exportTable struct {
	Table string
	Where string // $1 is the user id
	Omit  map[string]bool
}

// exportTables lists every table with a column that references users. The
// GDPR integration tests derive that set from information_schema and fail
// when this list (or Purge) misses one.
var exportTables = []exportTable{
	{Table: "users", Where: "id = $1"},
	{Table: "auth_identities", Where: "user_id = $1"},
	{Table: "sessions", Where: "user_id = $1", Omit: map[string]bool{"token_hash": true}},
	{Table: "devices", Where: "user_id = $1"},
	{Table: "device_lists", Where: "user_id = $1"},
	{Table: "wraps", Where: "user_id = $1 OR sender_id = $1"},
	{Table: "recovery_boxes", Where: "user_id = $1"},
	{Table: "practice_logs", Where: "user_id = $1"},
	{Table: "streak_statements", Where: "user_id = $1"},
	{Table: "invites", Where: "inviter_id = $1", Omit: map[string]bool{"auth_key_hash": true}},
	{Table: "invite_redemptions", Where: "inviter_id = $1 OR invitee_id = $1"},
	{Table: "friendships", Where: "user_a = $1 OR user_b = $1"},
	{Table: "blocks", Where: "blocker_id = $1"},   // blocks made, never who blocked the caller
	{Table: "reports", Where: "reporter_id = $1"}, // reports filed, never reports about the caller
	{Table: "push_tokens", Where: "user_id = $1"},
	{Table: "nudges", Where: "sender_id = $1 OR recipient_id = $1"},
}

// ExportTables returns the names of the exported tables.
func ExportTables() []string {
	out := make([]string, 0, len(exportTables))
	for _, t := range exportTables {
		out = append(out, t.Table)
	}
	return out
}

// Export returns every row held about the user, table by table, with
// column names as stored: bytea as standard base64, uuids in hex form,
// timestamps as RFC 3339 UTC, dates as YYYY-MM-DD, xid8 as decimal strings.
// It reads in one REPEATABLE READ snapshot so the tables agree.
func (s *Store) Export(ctx context.Context, userID string) (map[string][]map[string]any, error) {
	out := map[string][]map[string]any{}
	err := db.Tx(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		for _, t := range exportTables {
			rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT * FROM %s WHERE %s`, pgx.Identifier{t.Table}.Sanitize(), t.Where), userID)
			if err != nil {
				return err
			}
			list := []map[string]any{}
			for rows.Next() {
				vals, err := rows.Values()
				if err != nil {
					rows.Close()
					return err
				}
				row := map[string]any{}
				for i, fd := range rows.FieldDescriptions() {
					if !t.Omit[fd.Name] {
						row[fd.Name] = exportValue(fd.DataTypeOID, vals[i])
					}
				}
				list = append(list, row)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			out[t.Table] = list
		}
		return nil
	})
	return out, err
}

const oidDate = 1082

func exportValue(oid uint32, v any) any {
	switch x := v.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case [16]byte:
		return ids.UUID(x).String()
	case uint64:
		return strconv.FormatUint(x, 10)
	case time.Time:
		if oid == oidDate {
			return x.Format("2006-01-02")
		}
		return x.UTC().Format(time.RFC3339Nano)
	default:
		return v
	}
}

// Purge deletes every row of the user in one transaction (GDPR Art. 17):
// the account and everything that references it, both sides of
// friendships, blocks and nudges, and pending sign-in links to the user's
// addresses. In the invite tree, and as the subject of others' reports, the
// user is replaced by one new anonymous placeholder, so others' "invited by"
// stays consistent; acceptances the user signed are dropped. purge_log keeps
// SHA-256 of the user id so a restored backup can purge again. It returns
// the user's Sign in with Apple subjects, for revocation.
func (s *Store) Purge(ctx context.Context, userID string) (appleSubjects []string, err error) {
	uid, err := ids.ParseUUID(userID)
	if err != nil {
		return nil, ErrNotFound
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND NOT placeholder FOR UPDATE)`, userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `SELECT subject FROM auth_identities WHERE user_id = $1 AND provider = 'apple'`, userID)
		if err != nil {
			return err
		}
		if appleSubjects, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}

		var referenced bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM invite_redemptions WHERE inviter_id = $1 OR invitee_id = $1)
			OR EXISTS (SELECT 1 FROM reports WHERE reported_id = $1)`, userID).Scan(&referenced); err != nil {
			return err
		}
		if referenced {
			placeholder := ids.NewV7().String()
			if _, err := tx.Exec(ctx, `INSERT INTO users (id, display_name, placeholder) VALUES ($1, '', true)`, placeholder); err != nil {
				return err
			}
			for _, q := range []string{
				`UPDATE invite_redemptions SET inviter_id = $2 WHERE inviter_id = $1`,
				`UPDATE invite_redemptions SET invitee_id = $2, acceptance_payload = NULL, acceptance_signature = NULL WHERE invitee_id = $1`,
				`UPDATE reports SET reported_id = $2 WHERE reported_id = $1`,
			} {
				if _, err := tx.Exec(ctx, q, userID, placeholder); err != nil {
					return err
				}
			}
		}

		for _, q := range []string{
			`DELETE FROM magic_links WHERE email IN (SELECT email FROM auth_identities WHERE user_id = $1 AND email IS NOT NULL)`,
			`DELETE FROM signup_tokens WHERE email IN (SELECT email FROM auth_identities WHERE user_id = $1 AND email IS NOT NULL)`,
			`DELETE FROM nudges WHERE sender_id = $1 OR recipient_id = $1`,
			`DELETE FROM push_tokens WHERE user_id = $1`,
			`DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1`,
			`DELETE FROM reports WHERE reporter_id = $1`,
			`DELETE FROM friendships WHERE user_a = $1 OR user_b = $1`,
			`DELETE FROM invites WHERE inviter_id = $1`,
			`DELETE FROM streak_statements WHERE user_id = $1`,
			`DELETE FROM practice_logs WHERE user_id = $1`,
			`DELETE FROM recovery_boxes WHERE user_id = $1`,
			`DELETE FROM wraps WHERE user_id = $1 OR sender_id = $1`,
			`DELETE FROM device_lists WHERE user_id = $1`,
			`DELETE FROM sessions WHERE user_id = $1`,
			`DELETE FROM devices WHERE user_id = $1`,
			`DELETE FROM auth_identities WHERE user_id = $1`,
			`DELETE FROM users WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, q, userID); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO purge_log (user_hash) VALUES ($1) ON CONFLICT DO NOTHING`, uid.Hash())
		return err
	})
	return appleSubjects, err
}

// ReapplyPurges deletes, again, every account whose id hash is in purge_log.
// It matters only after restoring a backup taken before a purge.
func (s *Store) ReapplyPurges(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT u.id::text FROM users u
		JOIN purge_log p ON p.user_hash = sha256(uuid_send(u.id))
		WHERE NOT u.placeholder`)
	if err != nil {
		return 0, err
	}
	victims, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	for _, id := range victims {
		if _, err := s.Purge(ctx, id); err != nil {
			return 0, err
		}
	}
	return len(victims), nil
}
