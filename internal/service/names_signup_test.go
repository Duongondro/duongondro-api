package service

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/oidc"
	"github.com/Duongondro/duongondro-api/internal/service/names"
)

// isRandomName reports whether name is an adjective and an animal from the lists.
func isRandomName(name string) bool {
	adj, animal, ok := strings.Cut(name, " ")
	return ok && slices.Contains(names.Adjectives, adj) && slices.Contains(names.Animals, animal)
}

// Every sign-up path names an account that gives no name, and keeps a given one; the
// name is sealed like any display name.
func TestSignUpNamesAnAccount(t *testing.T) {
	f := setup(t)
	// Built as every sign-in test builds it, and signing up with admission codes, so
	// the test holds whether or not open sign-up needs configuring.
	verifier := fakeVerifier{claims: map[string]oidc.Claims{}}
	mailer := &fakeMailer{sent: make(chan string, 16)}
	s, _ := f.signIn(map[string]TokenVerifier{"google": verifier}, mailer, nil)
	ctx := t.Context()
	code := func() SignUpProof {
		typed, _ := f.admissionCode(time.Hour)
		return SignUpProof{AdmissionCode: typed}
	}
	nameOf := func(id uuid.UUID) string {
		t.Helper()
		u, err := f.keys.User(f.q.GetUser(ctx, id))
		if err != nil {
			t.Fatal(err)
		}
		return u.DisplayName
	}

	for _, given := range []*string{nil, new(""), new("  "), new("\u200b \u200e"), new("...")} {
		c, err := s.BeginPasskeySignUp(ctx, code(), SignUpProfile{DisplayName: given})
		if err != nil {
			t.Fatal(err)
		}
		session, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
		if err != nil {
			t.Fatal(err)
		}
		if name := nameOf(session.UserID); !isRandomName(name) {
			t.Fatalf("passkey sign-up with display name %v: %q", given, name)
		}
	}
	ana := "Ana"
	c, err := s.BeginPasskeySignUp(ctx, code(), SignUpProfile{DisplayName: &ana})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
	if err != nil || nameOf(session.UserID) != "Ana" {
		t.Fatalf("a given name was not kept: %v %q", err, nameOf(session.UserID))
	}

	if err := s.RequestMagicLink(ctx, "named@example.com", new(code()), "https://duongondro.app/m#"); err != nil {
		t.Fatal(err)
	}
	_, token := mailOf(t, mailer)
	viaMail, err := s.RedeemMagicLink(ctx, token)
	if err != nil || !isRandomName(nameOf(viaMail.UserID)) {
		t.Fatalf("magic-link sign-up: %v %q", err, nameOf(viaMail.UserID))
	}

	nonce, _ := s.NewNonce(ctx)
	verifier.claims["named"] = oidc.Claims{Subject: "g-named", Nonce: nonce}
	viaGoogle, err := s.ProviderSignIn(ctx, "google", "named", nonce, "", new(code()))
	if err != nil || !isRandomName(nameOf(viaGoogle.UserID)) {
		t.Fatalf("Google sign-up: %v %q", err, nameOf(viaGoogle.UserID))
	}

	// Sealed at rest: the stored bytes do not contain the name.
	var sealed []byte
	if err := f.pool.QueryRow(ctx, `SELECT display_name_encrypted FROM users WHERE id = $1`, viaGoogle.UserID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte(nameOf(viaGoogle.UserID))) {
		t.Fatalf("the name is not sealed: %x", sealed)
	}
}

// A ceremony row whose sealed display name opens to "" (none given) does not clear
// the random name at finish.
func TestSignUpCeremonyWithEmptyName(t *testing.T) {
	f := setup(t)
	s, _ := f.signIn(nil, nil, nil)
	ctx := t.Context()
	typed, _ := f.admissionCode(time.Hour)
	c, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: typed}, SignUpProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE webauthn_sessions SET display_name_encrypted = $2 WHERE id = $1`, c.SessionID,
		f.keys.SealString(atrest.WebauthnSessionsDisplayName, atrest.IDRow(c.SessionID), "")); err != nil {
		t.Fatal(err)
	}
	session, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
	if err != nil {
		t.Fatal(err)
	}
	if u, err := f.keys.User(f.q.GetUser(ctx, session.UserID)); err != nil || !isRandomName(u.DisplayName) {
		t.Fatalf("an empty ceremony name cleared the random one: %q %v", u.DisplayName, err)
	}
}
