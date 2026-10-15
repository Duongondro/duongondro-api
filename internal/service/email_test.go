package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
)

const (
	signInBase  = "https://duongondro.app/m#"
	confirmBase = "https://duongondro.app/m/e#"
)

// confirmMail waits for the next mail, checks it is a confirmation to want, and
// returns its code and token.
func confirmMail(t *testing.T, m *fakeMailer, want string) (code, token string) {
	t.Helper()
	select {
	case last := <-m.sent:
		parts := strings.SplitN(last, " ", 4) // to, code (two groups), link
		if parts[0] != want || !strings.HasPrefix(parts[3], confirmBase) {
			t.Fatalf("mail %q, want a confirmation to %s", last, want)
		}
		return parts[1] + " " + parts[2], strings.TrimPrefix(parts[3], confirmBase)
	case <-time.After(5 * time.Second):
		t.Fatal("no mail was sent")
		return "", ""
	}
}

func noMail(t *testing.T, m *fakeMailer) {
	t.Helper()
	select {
	case last := <-m.sent:
		t.Fatalf("unexpected mail %q", last)
	case <-time.After(100 * time.Millisecond):
	}
}

func (f *fixture) passkey(id uuid.UUID) {
	f.t.Helper()
	credID := random(16)
	if err := f.q.CreateCredential(f.t.Context(), db.CreateCredentialParams{ID: credID, UserID: id,
		DataEncrypted: f.keys.Seal(atrest.CredentialsData, atrest.RowOf(credID), []byte(`{}`))}); err != nil {
		f.t.Fatal(err)
	}
}

func emailOf(t *testing.T, s *SignIn, id uuid.UUID) string {
	t.Helper()
	e, err := s.Email(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if e == nil {
		return ""
	}
	return *e
}

func TestConfirmLinkBase(t *testing.T) {
	for base, want := range map[string]string{
		"https://duongondro.app/m#":  "https://duongondro.app/m/e#",
		"http://localhost:8080/m/#":  "http://localhost:8080/m/e#",
		"https://duongondro.app/m/":  "https://duongondro.app/m/e/",
		"https://example.test/x?t=#": "https://example.test/x?t=/e#",
	} {
		if got := ConfirmLinkBase(base); got != want {
			t.Errorf("ConfirmLinkBase(%q) = %q, want %q", base, got, want)
		}
	}
}

// An account without an address adds one by the typed code, and then signs in with
// it by magic link, link or code.
func TestAddEmailThenSignInWithIt(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()

	if err := s.RequestEmailConfirmation(ctx, ana.ID, " Ana@Example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	code, token := confirmMail(t, mailer, "ana@example.com")
	// The confirmation never signs in, by link or by code, and no other account can use it.
	if _, err := s.RedeemMagicLink(ctx, token); !isValidation(err) {
		t.Fatalf("a confirmation link signed in: %v", err)
	}
	if _, err := s.RedeemMagicLinkCode(ctx, "ana@example.com", code); !isValidation(err) {
		t.Fatalf("a confirmation code signed in: %v", err)
	}
	bo := f.user()
	if err := s.ConfirmEmailLink(ctx, bo.ID, token); !isValidation(err) {
		t.Fatalf("another account used the link: %v", err)
	}
	if err := s.ConfirmEmailCode(ctx, bo.ID, code); !isValidation(err) {
		t.Fatalf("another account used the code: %v", err)
	}
	if emailOf(t, s, ana.ID) != "" {
		t.Fatal("the address was added before it was confirmed")
	}
	if err := s.ConfirmEmailCode(ctx, ana.ID, strings.ToLower(strings.Replace(code, " ", "-", 1))); err != nil {
		t.Fatalf("confirming by code: %v", err)
	}
	if got := emailOf(t, s, ana.ID); got != "ana@example.com" {
		t.Fatalf("email %q", got)
	}
	// Single use: neither the code nor the link works again.
	if err := s.ConfirmEmailCode(ctx, ana.ID, code); !isValidation(err) {
		t.Fatalf("a code used twice: %v", err)
	}
	if err := s.ConfirmEmailLink(ctx, ana.ID, token); !isValidation(err) {
		t.Fatalf("the link after its code: %v", err)
	}

	// Stored as a magic-link sign-up stores it: sealed, keyed by the blind index.
	identities, err := f.keys.Identities(f.q.ListIdentities(ctx, ana.ID))
	if err != nil || len(identities) != 1 {
		t.Fatalf("identities %+v, %v", identities, err)
	}
	if i := identities[0]; i.Provider != "email" || i.Subject != "ana@example.com" || i.Email == nil || *i.Email != "ana@example.com" ||
		!bytes.Equal(i.SubjectHash, f.keys.HashString("ana@example.com")) {
		t.Fatalf("identity %+v", i)
	}

	// Asking again for the address the account has mails nothing.
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "ANA@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	noMail(t, mailer)

	// Sign-in by magic link, by code and by link.
	if err := s.RequestMagicLink(ctx, "ana@example.com", nil, signInBase); err != nil {
		t.Fatal(err)
	}
	code, _ = mailOf(t, mailer)
	session, err := s.RedeemMagicLinkCode(ctx, "ana@example.com", code)
	if err != nil || session.UserID != ana.ID || session.Created {
		t.Fatalf("sign-in by code: %+v %v", session, err)
	}
	if err := s.RequestMagicLink(ctx, "ana@example.com", nil, signInBase); err != nil {
		t.Fatal(err)
	}
	_, token = mailOf(t, mailer)
	if session, err := s.RedeemMagicLink(ctx, token); err != nil || session.UserID != ana.ID {
		t.Fatalf("sign-in by link: %+v %v", session, err)
	}
}

// The link does what the code does, for the account that asked.
func TestAddEmailByLink(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "ana@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	code, token := confirmMail(t, mailer, "ana@example.com")
	if err := s.ConfirmEmailLink(ctx, ana.ID, token); err != nil {
		t.Fatal(err)
	}
	if emailOf(t, s, ana.ID) != "ana@example.com" {
		t.Fatal("not added")
	}
	if err := s.ConfirmEmailCode(ctx, ana.ID, code); !isValidation(err) {
		t.Fatalf("the code after its link: %v", err)
	}
}

// Another account's address: the request looks like any other (204, mailed), and
// the confirmation, which proves the inbox, says 409. Nothing changes.
func TestAddEmailOfAnotherAccount(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana, bo := f.user(), f.user()
	if err := s.RequestEmailConfirmation(ctx, bo.ID, "bo@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	code, _ := confirmMail(t, mailer, "bo@example.com")
	if err := s.ConfirmEmailCode(ctx, bo.ID, code); err != nil {
		t.Fatal(err)
	}

	if err := s.RequestEmailConfirmation(ctx, ana.ID, "bo@example.com", confirmBase); err != nil {
		t.Fatalf("the request must not tell another account's address apart: %v", err)
	}
	code, _ = confirmMail(t, mailer, "bo@example.com")
	if err := s.ConfirmEmailCode(ctx, ana.ID, code); !isConflict(err) {
		t.Fatalf("confirming another account's address by code: %v", err)
	}
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "bo@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	_, token := confirmMail(t, mailer, "bo@example.com")
	if err := s.ConfirmEmailLink(ctx, ana.ID, token); !isConflict(err) {
		t.Fatalf("confirming another account's address by link: %v", err)
	}
	if emailOf(t, s, ana.ID) != "" || emailOf(t, s, bo.ID) != "bo@example.com" {
		t.Fatal("the address moved")
	}
}

// A second confirmed address replaces the first, which no longer signs in.
func TestReplaceEmail(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	for _, addr := range []string{"old@example.com", "new@example.com"} {
		if err := s.RequestEmailConfirmation(ctx, ana.ID, addr, confirmBase); err != nil {
			t.Fatal(err)
		}
		code, _ := confirmMail(t, mailer, addr)
		if err := s.ConfirmEmailCode(ctx, ana.ID, code); err != nil {
			t.Fatal(err)
		}
	}
	identities, err := f.keys.Identities(f.q.ListIdentities(ctx, ana.ID))
	if err != nil || len(identities) != 1 || identities[0].Subject != "new@example.com" {
		t.Fatalf("identities %+v, %v", identities, err)
	}
	// The old address has no account any more: a sign-in mail is not sent.
	if err := s.RequestMagicLink(ctx, "old@example.com", nil, signInBase); err != nil {
		t.Fatal(err)
	}
	noMail(t, mailer)
	if err := s.RequestMagicLink(ctx, "new@example.com", nil, signInBase); err != nil {
		t.Fatal(err)
	}
	code, _ := mailOf(t, mailer)
	if session, err := s.RedeemMagicLinkCode(ctx, "new@example.com", code); err != nil || session.UserID != ana.ID {
		t.Fatalf("sign-in with the new address: %v", err)
	}
	// A newer confirmation request kills the account's older code.
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "a@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	older, olderToken := confirmMail(t, mailer, "a@example.com")
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "b@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	newer, _ := confirmMail(t, mailer, "b@example.com")
	if err := s.ConfirmEmailCode(ctx, ana.ID, older); !isValidation(err) {
		t.Fatalf("an older code after a newer mail: %v", err)
	}
	if err := s.ConfirmEmailCode(ctx, ana.ID, newer); err != nil || emailOf(t, s, ana.ID) != "b@example.com" {
		t.Fatalf("the newer code: %v", err)
	}
	// The older link still works, for the account that asked.
	if err := s.ConfirmEmailLink(ctx, ana.ID, olderToken); err != nil || emailOf(t, s, ana.ID) != "a@example.com" {
		t.Fatalf("the older link: %v", err)
	}
}

// Five wrong codes kill the code, as for sign-in codes; the link still works.
func TestConfirmationCodeLockout(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "ana@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	code, token := confirmMail(t, mailer, "ana@example.com")
	if err := s.ConfirmEmailCode(ctx, ana.ID, "ABC"); !isValidation(err) {
		t.Fatalf("a malformed code: %v", err)
	}
	for i := 0; i < maxWrongCodes; i++ {
		if err := s.ConfirmEmailCode(ctx, ana.ID, wrongCode(code)); !isValidation(err) {
			t.Fatalf("wrong code %d: %v", i+1, err)
		}
	}
	if err := s.ConfirmEmailCode(ctx, ana.ID, code); !isValidation(err) {
		t.Fatalf("the right code after five wrong ones: %v", err)
	}
	if emailOf(t, s, ana.ID) != "" {
		t.Fatal("added after the code died")
	}
	if err := s.ConfirmEmailLink(ctx, ana.ID, token); err != nil {
		t.Fatalf("the link after the code died: %v", err)
	}
}

// Expired confirmations are refused like wrong ones.
func TestConfirmationExpires(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "ana@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	code, token := confirmMail(t, mailer, "ana@example.com")
	if _, err := f.pool.Exec(ctx, `UPDATE magic_links SET created_at = now() - interval '16 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmEmailCode(ctx, ana.ID, code); !isValidation(err) {
		t.Fatalf("an expired code: %v", err)
	}
	if err := s.ConfirmEmailLink(ctx, ana.ID, token); !isValidation(err) {
		t.Fatalf("an expired link: %v", err)
	}
}

// Three mails per address per 15 minutes, sign-in mails included.
func TestConfirmationLimits(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana, bo := f.user(), f.user()
	for i := 0; i < magicLinksPerWindow; i++ {
		if err := s.RequestEmailConfirmation(ctx, ana.ID, "x@example.com", confirmBase); err != nil {
			t.Fatal(err)
		}
		confirmMail(t, mailer, "x@example.com")
	}
	if err := s.RequestEmailConfirmation(ctx, bo.ID, "x@example.com", confirmBase); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("a fourth mail to one address: %v", err)
	}
	if err := s.RequestMagicLink(ctx, "x@example.com", &openProof, signInBase); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("a sign-in mail after three confirmations: %v", err)
	}
	noMail(t, mailer)
}

// Five confirmation requests per account an hour.
func TestConfirmationAccountLimit(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	for i := range EmailConfirmationLimit {
		addr := string(rune('a'+i)) + "@example.com"
		if err := s.RequestEmailConfirmation(ctx, ana.ID, addr, confirmBase); err != nil {
			t.Fatal(err)
		}
		confirmMail(t, mailer, addr)
	}
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "more@example.com", confirmBase); !errors.Is(err, ErrEmailConfirmationRateLimited) {
		t.Fatalf("a sixth confirmation within the hour: %v", err)
	}
	noMail(t, mailer)
	// Another account is not limited by ana's.
	bo := f.user()
	if err := s.RequestEmailConfirmation(ctx, bo.ID, "more@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	confirmMail(t, mailer, "more@example.com")
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "not an address", confirmBase); !isValidation(err) {
		t.Fatalf("a bad address: %v", err)
	}
}

// Removing the address: refused while it is the only way to sign in.
func TestRemoveEmail(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	if err := s.RemoveEmail(ctx, ana.ID); err != nil {
		t.Fatalf("removing no address: %v", err)
	}
	// An account made by a magic link has only its address.
	if err := s.RequestMagicLink(ctx, "solo@example.com", &openProof, signInBase); err != nil {
		t.Fatal(err)
	}
	code, _ := mailOf(t, mailer)
	solo, err := s.RedeemMagicLinkCode(ctx, "solo@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveEmail(ctx, solo.UserID); !isConflict(err) {
		t.Fatalf("removing the only way to sign in: %v", err)
	}
	f.passkey(solo.UserID)
	if err := s.RemoveEmail(ctx, solo.UserID); err != nil {
		t.Fatal(err)
	}
	if emailOf(t, s, solo.UserID) != "" {
		t.Fatal("still there")
	}
	if err := s.RequestMagicLink(ctx, "solo@example.com", nil, signInBase); err != nil {
		t.Fatal(err)
	}
	noMail(t, mailer)
}

// The export shows the address and a pending confirmation; a purge removes both.
func TestEmailExportAndPurge(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := t.Context()
	ana := f.user()
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "ana@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	code, _ := confirmMail(t, mailer, "ana@example.com")
	if err := s.ConfirmEmailCode(ctx, ana.ID, code); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestEmailConfirmation(ctx, ana.ID, "pending@example.com", confirmBase); err != nil {
		t.Fatal(err)
	}
	confirmMail(t, mailer, "pending@example.com")
	gdpr := NewGDPR(f.pool, f.keys)
	export, err := gdpr.Export(ctx, ana.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(export.AuthIdentities) != 1 || export.AuthIdentities[0].Subject != "ana@example.com" {
		t.Fatalf("export identities %+v", export.AuthIdentities)
	}
	found := false
	for _, m := range export.MagicLinks {
		found = found || m.Email == "pending@example.com"
	}
	if !found {
		t.Fatalf("the pending confirmation is not exported: %+v", export.MagicLinks)
	}
	if err := gdpr.Purge(ctx, ana.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth_identities) + (SELECT count(*) FROM magic_links)`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d identity or link rows remain after the purge", n)
	}
}

// failingMailer fails every send, so the warning is logged.
type failingMailer struct{ fakeMailer }

func (failingMailer) SendEmailConfirmation(context.Context, string, string, string) error {
	return errors.New("relay refused")
}

// The address is never stored or logged in clear: not in any row (as text or hex
// of its bytes), not in the log line of a failed mail.
func TestEmailNeverInClear(t *testing.T) {
	f := setup(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	mailer := &failingMailer{}
	s, _ := f.signIn(nil, mailer, nil)
	ctx := t.Context()
	ana := f.user()
	const addr = "secret.person@example.com"
	if err := s.RequestEmailConfirmation(ctx, ana.ID, addr, confirmBase); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "e-mail confirmation failed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "e-mail confirmation failed") {
		t.Fatalf("no warning logged: %s", logs.String())
	}
	if strings.Contains(strings.ToLower(logs.String()), "secret.person") {
		t.Fatalf("the address was logged: %s", logs.String())
	}
	// Confirm it, through the row directly, as no code was mailed.
	if err := s.attachEmail(ctx, ana.ID, addr); err != nil {
		t.Fatal(err)
	}
	var clear int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM magic_links m WHERE m::text ILIKE '%secret.person%' OR encode(m.email_encrypted, 'escape') ILIKE '%secret.person%')
		+ (SELECT count(*) FROM auth_identities a WHERE a::text ILIKE '%secret.person%'
			OR encode(a.subject_encrypted, 'escape') ILIKE '%secret.person%' OR encode(a.email_encrypted, 'escape') ILIKE '%secret.person%')`).Scan(&clear); err != nil {
		t.Fatal(err)
	}
	if clear != 0 {
		t.Fatalf("%d rows hold the address in clear", clear)
	}
	var rows int
	_ = f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_links WHERE user_id = $1) + (SELECT count(*) FROM auth_identities WHERE user_id = $1)`, ana.ID).Scan(&rows)
	if rows != 2 {
		t.Fatalf("%d rows, want the pending confirmation and the identity", rows)
	}
}
