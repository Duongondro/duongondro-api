package service

import (
	"errors"
	"testing"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
)

func TestPasskeyManagement(t *testing.T) {
	f := setup(t)
	s, _ := f.signIn(nil, nil, nil)
	a := auth.New(f.pool, f.keys)
	ctx := t.Context()
	ana, bo := f.member(), f.member()
	// The AAGUID as go-webauthn stores it: base64 in the credential's JSON.
	google := []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4}
	addPasskey := func(userID [16]byte, data string) []byte {
		id := random(16)
		if err := f.q.CreateCredential(ctx, db.CreateCredentialParams{ID: id, UserID: userID,
			DataEncrypted: f.keys.Seal(atrest.CredentialsData, atrest.RowOf(id), []byte(data))}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	phone := addPasskey(ana.ID, `{"authenticator":{"AAGUID":"6puNZk0BHSE85La0jLV11A=="}}`)
	laptop := addPasskey(ana.ID, `{"authenticator":{"AAGUID":"AAAAAAAAAAAAAAAAAAAAAA=="}}`)
	bos := addPasskey(bo.ID, `{}`)

	viaPhone, err := a.NewPasskeySession(ctx, ana.ID, phone)
	if err != nil {
		t.Fatal(err)
	}
	viaLink, err := a.NewSession(ctx, ana.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Listing: oldest first, the AAGUID when it is not all zeros, the session's own.
	current, err := a.SessionCredential(ctx, viaPhone)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := s.Passkeys(ctx, ana.ID, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || string(keys[0].ID) != string(phone) || !keys[0].Current || keys[1].Current {
		t.Fatalf("passkeys: %+v", keys)
	}
	if keys[0].AAGUID == nil || string(keys[0].AAGUID[:]) != string(google) || keys[1].AAGUID != nil {
		t.Fatalf("AAGUIDs: %v, %v", keys[0].AAGUID, keys[1].AAGUID)
	}
	if c, _ := a.SessionCredential(ctx, viaLink); c != nil {
		t.Fatal("a magic-link session names a passkey")
	}

	// Renaming: trimmed, sealed, cleared by blank; bounded; only one's own.
	name := "  Laptop key  "
	if err := s.RenamePasskey(ctx, ana.ID, laptop, &name); err != nil {
		t.Fatal(err)
	}
	keys, _ = s.Passkeys(ctx, ana.ID, nil)
	if keys[1].Name == nil || *keys[1].Name != "Laptop key" {
		t.Fatalf("renamed: %v", keys[1].Name)
	}
	long := string(make([]rune, 65))
	if err := s.RenamePasskey(ctx, ana.ID, laptop, &long); !isValidation(err) {
		t.Fatalf("a 65-character name: %v", err)
	}
	if err := s.RenamePasskey(ctx, ana.ID, bos, &name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("renaming someone else's passkey: %v", err)
	}
	blank := " "
	if err := s.RenamePasskey(ctx, ana.ID, laptop, &blank); err != nil {
		t.Fatal(err)
	}
	if keys, _ = s.Passkeys(ctx, ana.ID, nil); keys[1].Name != nil {
		t.Fatalf("a blank name was kept: %q", *keys[1].Name)
	}

	// Removing ends the sessions it signed in with, and only those.
	if err := s.RemovePasskey(ctx, ana.ID, bos); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing someone else's passkey: %v", err)
	}
	if err := s.RemovePasskey(ctx, ana.ID, phone); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SessionUser(ctx, viaPhone); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("the removed passkey's session lives on: %v", err)
	}
	if _, err := a.SessionUser(ctx, viaLink); err != nil {
		t.Fatalf("another session ended: %v", err)
	}

	// The last way to sign in stays.
	var conflictErr *ConflictError
	if err := s.RemovePasskey(ctx, ana.ID, laptop); !errors.As(err, &conflictErr) {
		t.Fatalf("removing the last passkey of an account without e-mail: %v", err)
	}
	if keys, _ = s.Passkeys(ctx, ana.ID, nil); len(keys) != 1 {
		t.Fatalf("the refused removal took effect: %+v", keys)
	}
	email := "ana@example.com"
	hash := f.keys.HashString(email)
	row := atrest.IdentityRow("email", hash)
	if err := f.q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: "email", UserID: ana.ID,
		SubjectEncrypted: f.keys.SealString(atrest.AuthIdentitiesSubject, row, email), SubjectHash: hash,
		EmailEncrypted: f.keys.SealString(atrest.AuthIdentitiesEmail, row, email), EmailHash: hash}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemovePasskey(ctx, ana.ID, laptop); err != nil {
		t.Fatalf("with an e-mail, the last passkey can go: %v", err)
	}
}
