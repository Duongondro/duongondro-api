package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
)

// Passkey is one of an account's passkeys as Settings › Passkeys lists it (design
// decision 25): no key material.
type Passkey struct {
	ID         []byte
	Name       *string    // nil: the app names it after its password manager
	AAGUID     *uuid.UUID // nil when the authenticator gave none
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Current    bool // the asking session signed in with it
}

// Passkeys lists the account's passkeys, oldest first; current is the credential the
// asking session signed in with, nil for a session from a magic link.
func (s *SignIn) Passkeys(ctx context.Context, userID uuid.UUID, current []byte) ([]Passkey, error) {
	rows, err := s.keys.Credentials(s.q.ListCredentials(ctx, userID))
	if err != nil {
		return nil, err
	}
	out := make([]Passkey, len(rows))
	for i, r := range rows {
		out[i] = Passkey{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt,
			Current: current != nil && string(current) == string(r.ID)}
		var c webauthn.Credential
		if json.Unmarshal(r.Data, &c) == nil {
			out[i].AAGUID = aaguid(c.Authenticator.AAGUID)
		}
	}
	return out, nil
}

// aaguid is the authenticator's AAGUID, or nil when it is missing or all zeros (no
// attestation, as most passkey providers send).
func aaguid(b []byte) *uuid.UUID {
	var id uuid.UUID
	if len(b) != len(id) {
		return nil
	}
	copy(id[:], b)
	if id == (uuid.UUID{}) {
		return nil
	}
	return &id
}

// maxPasskeyName bounds a passkey's name, in characters, as display names are bounded.
const maxPasskeyName = 64

// RenamePasskey names one of the account's passkeys; nil or blank clears the name.
// The name is sealed at rest, bound to the credential's row.
func (s *SignIn) RenamePasskey(ctx context.Context, userID uuid.UUID, id []byte, name *string) error {
	var sealed []byte
	if name != nil {
		n := strings.TrimSpace(*name)
		if !validText(n) || utf8.RuneCountInString(n) > maxPasskeyName {
			return invalid("a passkey's name must be valid text of at most %d characters", maxPasskeyName)
		}
		if n != "" {
			sealed = s.keys.SealString(atrest.CredentialsName, atrest.RowOf(id), n)
		}
	}
	n, err := s.q.RenameCredential(ctx, db.RenameCredentialParams{ID: id, UserID: userID, NameEncrypted: sealed})
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

// RemovePasskey deletes one of the account's passkeys, and with it every session it
// signed in with (sessions.credential_id cascades). It refuses to remove the last way
// to sign in: an account with no other passkey, e-mail, Apple or Google identity
// keeps its only passkey.
func (s *SignIn) RemovePasskey(ctx context.Context, userID uuid.UUID, id []byte) error {
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		// Two removals at once must not both see a second method left.
		if _, err := q.LockUser(ctx, userID); err != nil {
			return err
		}
		// Its phones are signed out as a removed device is: no more nudges.
		if err := q.DropCredentialPushTokens(ctx, db.DropCredentialPushTokensParams{CredentialID: id, UserID: userID}); err != nil {
			return err
		}
		n, err := q.DeleteCredential(ctx, db.DeleteCredentialParams{ID: id, UserID: userID})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		left, err := q.CountSignInMethods(ctx, userID)
		if err != nil {
			return err
		}
		if left == 0 {
			return conflict("this is the account's last way to sign in; add another passkey or an e-mail, or link Apple or Google, first")
		}
		return nil
	})
}
