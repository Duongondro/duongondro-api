package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"uuid"

	"github.com/pressly/goose/v3"

	"github.com/Duongondro/duongondro-api/internal/atrest"
)

// EncryptColumnsBackfill is step 2 of 4 of encryption at rest: it seals every plain
// personal value into the columns step 1 added, and computes the blind indexes, in
// one transaction, so step 3 can drop the plain columns. SQL cannot call the
// crypter, hence a Go migration; it runs inside `server migrate`, which the service
// runs before it starts, so the deploy needs no extra step (only SECRET_KEY_BASE).
//
// It reads and writes this version's schema with plain SQL, never with sqlc's
// queries, which follow the latest schema: a fresh database runs it too.
//
// Passkey ceremonies in flight (five minutes at most, and the service is stopped
// while this runs) are deleted rather than sealed.
func EncryptColumnsBackfill(keys *atrest.Keys) *goose.Migration {
	return goose.NewGoMigration(20261014183131,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error { return backfill(ctx, tx, keys) }},
		nil) // never rolled back; fix forward, like the SQL migrations
}

func backfill(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	steps := []struct {
		name string
		fn   func(context.Context, *sql.Tx, *atrest.Keys) error
	}{
		{"users", backfillUsers}, {"devices", backfillDevices}, {"statements", backfillStatements},
		{"reports", backfillReports}, {"streaks", backfillStreaks}, {"credentials", backfillCredentials},
		{"auth_identities", backfillIdentities}, {"magic_links", backfillMagicLinks}, {"push_tokens", backfillPushTokens},
	}
	for _, s := range steps {
		if err := s.fn(ctx, tx, k); err != nil {
			return fmt.Errorf("sealing %s: %w", s.name, err)
		}
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM webauthn_sessions`)
	return err
}

// rows reads every row of query before the updates start: one connection cannot
// update while it still streams a result.
func rows[T any](ctx context.Context, tx *sql.Tx, query string, scan func(*sql.Rows) (T, error)) ([]T, error) {
	r, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []T
	for r.Next() {
		v, err := scan(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, r.Err()
}

func parseID(s string) (uuid.UUID, error) { return uuid.Parse(s) }

func backfillUsers(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type user struct {
		id               uuid.UUID
		identity         []byte
		displayName      string
		username, gender sql.NullString
	}
	all, err := rows(ctx, tx, `SELECT id::text, identity_public_key, display_name, username, gender FROM users`,
		func(r *sql.Rows) (u user, err error) {
			var id string
			if err = r.Scan(&id, &u.identity, &u.displayName, &u.username, &u.gender); err == nil {
				u.id, err = parseID(id)
			}
			return u, err
		})
	if err != nil {
		return err
	}
	for _, u := range all {
		row := atrest.IDRow(u.id)
		var identity, name, username, usernameHash, gender []byte
		if u.identity != nil {
			identity = k.Seal(atrest.UsersIdentityPublicKey, row, u.identity)
		}
		if u.displayName != "" {
			name = k.SealString(atrest.UsersDisplayName, row, u.displayName)
		}
		if u.username.Valid {
			username = k.SealString(atrest.UsersUsername, row, u.username.String)
			usernameHash = k.HashString(u.username.String)
		}
		if u.gender.Valid {
			gender = k.SealString(atrest.UsersGender, row, u.gender.String)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET identity_public_key_encrypted = $2, display_name_encrypted = $3,
			username_encrypted = $4, username_hash = $5, gender_encrypted = $6 WHERE id = $1`,
			u.id.String(), identity, name, username, usernameHash, gender); err != nil {
			return err
		}
	}
	return nil
}

func backfillDevices(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type device struct {
		id  uuid.UUID
		key []byte
	}
	all, err := rows(ctx, tx, `SELECT id::text, public_key FROM devices`, func(r *sql.Rows) (d device, err error) {
		var id string
		if err = r.Scan(&id, &d.key); err == nil {
			d.id, err = parseID(id)
		}
		return d, err
	})
	if err != nil {
		return err
	}
	for _, d := range all {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET public_key_encrypted = $2, public_key_hash = $3 WHERE id = $1`,
			d.id.String(), k.Seal(atrest.DevicesPublicKey, atrest.IDRow(d.id), d.key), k.Hash(d.key)); err != nil {
			return err
		}
	}
	return nil
}

// backfillStatements seals the payloads of device lists, invites and redemptions.
func backfillStatements(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type list struct {
		user    uuid.UUID
		payload []byte
	}
	lists, err := rows(ctx, tx, `SELECT user_id::text, payload FROM device_lists`, func(r *sql.Rows) (l list, err error) {
		var id string
		if err = r.Scan(&id, &l.payload); err == nil {
			l.user, err = parseID(id)
		}
		return l, err
	})
	if err != nil {
		return err
	}
	for _, l := range lists {
		if _, err := tx.ExecContext(ctx, `UPDATE device_lists SET payload_encrypted = $2 WHERE user_id = $1`,
			l.user.String(), k.Seal(atrest.DeviceListsPayload, atrest.IDRow(l.user), l.payload)); err != nil {
			return err
		}
	}

	type invite struct {
		id      string
		payload []byte
	}
	invites, err := rows(ctx, tx, `SELECT id, payload FROM invites`, func(r *sql.Rows) (i invite, err error) {
		return i, r.Scan(&i.id, &i.payload)
	})
	if err != nil {
		return err
	}
	for _, i := range invites {
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET payload_encrypted = $2 WHERE id = $1`,
			i.id, k.Seal(atrest.InvitesPayload, atrest.RowOf([]byte(i.id)), i.payload)); err != nil {
			return err
		}
	}

	type redemption struct {
		invite  string
		invitee uuid.UUID
		payload []byte
	}
	redemptions, err := rows(ctx, tx, `SELECT invite_id, invitee_id::text, payload FROM invite_redemptions`,
		func(r *sql.Rows) (x redemption, err error) {
			var id string
			if err = r.Scan(&x.invite, &id, &x.payload); err == nil {
				x.invitee, err = parseID(id)
			}
			return x, err
		})
	if err != nil {
		return err
	}
	for _, x := range redemptions {
		row := atrest.RowOf([]byte(x.invite), x.invitee[:])
		if _, err := tx.ExecContext(ctx, `UPDATE invite_redemptions SET payload_encrypted = $3 WHERE invite_id = $1 AND invitee_id = $2`,
			x.invite, x.invitee.String(), k.Seal(atrest.InviteRedemptionsPayload, row, x.payload)); err != nil {
			return err
		}
	}
	return nil
}

func backfillReports(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type report struct {
		id     uuid.UUID
		reason string
	}
	all, err := rows(ctx, tx, `SELECT id::text, reason FROM reports`, func(r *sql.Rows) (x report, err error) {
		var id string
		if err = r.Scan(&id, &x.reason); err == nil {
			x.id, err = parseID(id)
		}
		return x, err
	})
	if err != nil {
		return err
	}
	for _, x := range all {
		if _, err := tx.ExecContext(ctx, `UPDATE reports SET reason_encrypted = $2 WHERE id = $1`,
			x.id.String(), k.SealString(atrest.ReportsReason, atrest.IDRow(x.id), x.reason)); err != nil {
			return err
		}
	}
	return nil
}

func backfillStreaks(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type streak struct {
		user     uuid.UUID
		practice string
		payload  []byte
	}
	all, err := rows(ctx, tx, `SELECT user_id::text, practice, payload FROM streaks`, func(r *sql.Rows) (s streak, err error) {
		var id string
		if err = r.Scan(&id, &s.practice, &s.payload); err == nil {
			s.user, err = parseID(id)
		}
		return s, err
	})
	if err != nil {
		return err
	}
	for _, s := range all {
		hash := k.HashString(s.practice)
		row := atrest.RowOf(s.user[:], hash)
		if _, err := tx.ExecContext(ctx, `UPDATE streaks SET practice_encrypted = $3, practice_hash = $4, payload_encrypted = $5
			WHERE user_id = $1 AND practice = $2`, s.user.String(), s.practice,
			k.SealString(atrest.StreaksPractice, row, s.practice), hash, k.Seal(atrest.StreaksPayload, row, s.payload)); err != nil {
			return err
		}
	}
	return nil
}

func backfillCredentials(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type credential struct{ id, data []byte }
	all, err := rows(ctx, tx, `SELECT id, data::text FROM credentials`, func(r *sql.Rows) (c credential, err error) {
		var data string
		err = r.Scan(&c.id, &data)
		c.data = []byte(data)
		return c, err
	})
	if err != nil {
		return err
	}
	for _, c := range all {
		if _, err := tx.ExecContext(ctx, `UPDATE credentials SET data_encrypted = $2 WHERE id = $1`,
			c.id, k.Seal(atrest.CredentialsData, atrest.RowOf(c.id), c.data)); err != nil {
			return err
		}
	}
	return nil
}

func backfillIdentities(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type identity struct {
		provider, subject string
		email, refresh    sql.NullString
	}
	all, err := rows(ctx, tx, `SELECT provider, subject, email, refresh_token FROM auth_identities`,
		func(r *sql.Rows) (i identity, err error) {
			return i, r.Scan(&i.provider, &i.subject, &i.email, &i.refresh)
		})
	if err != nil {
		return err
	}
	for _, i := range all {
		subject := i.subject
		if i.provider == "email" {
			subject = atrest.NormaliseEmail(subject)
		}
		subjectHash := k.HashString(subject)
		row := atrest.RowOf([]byte(i.provider), subjectHash)
		var email, emailHash, refresh []byte
		if i.email.Valid {
			e := atrest.NormaliseEmail(i.email.String)
			email, emailHash = k.SealString(atrest.AuthIdentitiesEmail, row, e), k.HashString(e)
		}
		if i.refresh.Valid {
			refresh = k.SealString(atrest.AuthIdentitiesRefreshToken, row, i.refresh.String)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE auth_identities SET subject_encrypted = $3, subject_hash = $4,
			email_encrypted = $5, email_hash = $6, refresh_token_encrypted = $7 WHERE provider = $1 AND subject = $2`,
			i.provider, i.subject, k.SealString(atrest.AuthIdentitiesSubject, row, subject), subjectHash,
			email, emailHash, refresh); err != nil {
			return err
		}
	}
	return nil
}

func backfillMagicLinks(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type link struct {
		tokenHash []byte
		email     string
	}
	all, err := rows(ctx, tx, `SELECT token_hash, email FROM magic_links`, func(r *sql.Rows) (l link, err error) {
		return l, r.Scan(&l.tokenHash, &l.email)
	})
	if err != nil {
		return err
	}
	for _, l := range all {
		e := atrest.NormaliseEmail(l.email)
		if _, err := tx.ExecContext(ctx, `UPDATE magic_links SET email_encrypted = $2, email_hash = $3 WHERE token_hash = $1`,
			l.tokenHash, k.SealString(atrest.MagicLinksEmail, atrest.RowOf(l.tokenHash), e), k.HashString(e)); err != nil {
			return err
		}
	}
	return nil
}

func backfillPushTokens(ctx context.Context, tx *sql.Tx, k *atrest.Keys) error {
	type token struct {
		device uuid.UUID
		token  string
	}
	all, err := rows(ctx, tx, `SELECT device_id::text, token FROM push_tokens`, func(r *sql.Rows) (t token, err error) {
		var id string
		if err = r.Scan(&id, &t.token); err == nil {
			t.device, err = parseID(id)
		}
		return t, err
	})
	if err != nil {
		return err
	}
	for _, t := range all {
		if _, err := tx.ExecContext(ctx, `UPDATE push_tokens SET token_encrypted = $2, token_hash = $3 WHERE device_id = $1`,
			t.device.String(), k.SealString(atrest.PushTokensToken, atrest.IDRow(t.device), t.token), k.HashString(t.token)); err != nil {
			return err
		}
	}
	return nil
}
