package service

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"

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
	// A username and a gender without a display name keep the random name.
	user, gender := "nameless", "female"
	c, err := s.BeginPasskeySignUp(ctx, code(), SignUpProfile{Username: &user, Gender: &gender})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
	if err != nil {
		t.Fatal(err)
	}
	if u, err := f.keys.User(f.q.GetUser(ctx, session.UserID)); err != nil || !isRandomName(u.DisplayName) ||
		u.Username == nil || *u.Username != "nameless" || u.Gender == nil || *u.Gender != "female" {
		t.Fatalf("username and gender without a display name: %+v %v", u, err)
	}
	ana := "Ana"
	c, err = s.BeginPasskeySignUp(ctx, code(), SignUpProfile{DisplayName: &ana})
	if err != nil {
		t.Fatal(err)
	}
	session, err = s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
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

// A passkey sign-up's random name is drawn when the ceremony begins: it labels the
// passkey (the options' user) and becomes the account's name, the same one.
func TestPasskeyIsNamedLikeTheAccount(t *testing.T) {
	f := setup(t)
	s, _ := f.signIn(nil, nil, nil)
	ctx := t.Context()
	signUp := func(profile SignUpProfile) (user protocol.UserEntity, displayName string, username *string) {
		t.Helper()
		typed, _ := f.admissionCode(time.Hour)
		c, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: typed}, profile)
		if err != nil {
			t.Fatal(err)
		}
		user = c.Options.(*protocol.CredentialCreation).Response.User
		session, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
		if err != nil {
			t.Fatal(err)
		}
		u, err := f.keys.User(f.q.GetUser(ctx, session.UserID))
		if err != nil {
			t.Fatal(err)
		}
		return user, u.DisplayName, u.Username
	}

	seen := map[string]bool{}
	for range 3 {
		user, name, _ := signUp(SignUpProfile{})
		if !isRandomName(user.DisplayName) || user.Name != user.DisplayName || name != user.DisplayName {
			t.Fatalf("passkey labelled %q / %q, account named %q", user.Name, user.DisplayName, name)
		}
		seen[name] = true
	}
	if len(seen) < 2 {
		t.Fatal("every passkey got the same name")
	}
	// A username still names the passkey; the random display name goes beside it.
	username := "otterfan"
	user, name, stored := signUp(SignUpProfile{Username: &username})
	if user.Name != "otterfan" || !isRandomName(user.DisplayName) || name != user.DisplayName || stored == nil || *stored != "otterfan" {
		t.Fatalf("with a username: %q / %q, account %q", user.Name, user.DisplayName, name)
	}
	// A given name is used as before.
	ana := "Ana"
	if user, name, _ := signUp(SignUpProfile{DisplayName: &ana}); user.Name != "Ana" || user.DisplayName != "Ana" || name != "Ana" {
		t.Fatalf("with a name: %q / %q, account %q", user.Name, user.DisplayName, name)
	}
}
