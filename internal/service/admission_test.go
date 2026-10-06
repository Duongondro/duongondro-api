package service

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/oidc"
)

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{
		"abcd efgh-jkmn pqrs": "ABCDEFGHJKMNPQRS",
		"oO0 iIlL1\n":         "00011111",
		" 7k2m-q9xa ":         "7K2MQ9XA",
	} {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := FormatCode("ABCDEFGHJKMNPQRS"); got != "ABCD EFGH JKMN PQRS" {
		t.Errorf("FormatCode: %q", got)
	}
	code, err := randomCode(AdmissionCodeLength)
	if err != nil || len(code) != AdmissionCodeLength || strings.Trim(code, crockford) != "" || NormalizeCode(code) != code {
		t.Fatalf("randomCode: %q %v", code, err)
	}
}

// admissionCode stores one code and returns it as a person would type it: lower case, in
// groups, with an O for a zero and an L for a one.
func (f *fixture) admissionCode(lifetime time.Duration) (typed, normalized string) {
	codes, err := NewAdmissions(f.pool).Issue(f.t.Context(), 1, lifetime)
	if err != nil {
		f.t.Fatal(err)
	}
	typed = strings.ToLower(FormatCode(codes[0]))
	typed = strings.ReplaceAll(strings.ReplaceAll(typed, "0", "o"), "1", "l")
	return typed, codes[0]
}

func TestAdmissionCodes(t *testing.T) {
	f := setup(t)
	s, social := f.signIn(nil, nil, nil)
	ctx := t.Context()

	stored, _ := f.admissionCode(time.Hour)
	var hashes int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM admission_codes WHERE code_hash = sha256(convert_to($1, 'UTF8'))`,
		NormalizeCode(stored)).Scan(&hashes)
	if hashes != 1 {
		t.Fatal("the code is not stored as its SHA-256")
	}

	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: "ABCD"}); !isValidation(err) {
		t.Fatalf("a malformed code: %v", err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: strings.Repeat("Z", AdmissionCodeLength)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown code: %v", err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{}); !isValidation(err) {
		t.Fatalf("neither invite nor code: %v", err)
	}
	inviter := f.member()
	auth := f.invite(social, inviter, "R00TC0DE")
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{Invite: &InviteProof{ID: "R00TC0DE", Auth: auth}, AdmissionCode: stored}); !isValidation(err) {
		t.Fatalf("both invite and code: %v", err)
	}

	// A passkey sign-up with the code makes a root of the invite tree, without friends.
	phone := newAuthenticator()
	ceremony, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: stored})
	if err != nil {
		t.Fatal(err)
	}
	// A second ceremony with the same code may begin, but only one can finish.
	other := newAuthenticator()
	second, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: stored})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.FinishPasskey(ctx, ceremony.SessionID, phone.create(t, ceremony.Options))
	if err != nil || !session.Created {
		t.Fatalf("sign-up with an admission code: %v %+v", err, session)
	}
	var parent *string
	if err := f.pool.QueryRow(ctx, `SELECT parent_id::text FROM invite_tree WHERE user_id = $1`, session.UserID).Scan(&parent); err != nil || parent != nil {
		t.Fatalf("invite tree: %v parent %v", err, parent)
	}
	if friends, _ := social.Friends(ctx, session.UserID); len(friends) != 0 {
		t.Fatalf("an admitted account has %d friends", len(friends))
	}
	var usedBy string
	if err := f.pool.QueryRow(ctx, `SELECT used_by::text FROM admission_codes WHERE used_at IS NOT NULL`).Scan(&usedBy); err != nil || usedBy != session.UserID.String() {
		t.Fatalf("the code is not spent by the account: %v %s", err, usedBy)
	}
	if _, err := s.FinishPasskey(ctx, second.SessionID, other.create(t, second.Options)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spent code made a second account: %v", err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: stored}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spent code began a sign-up: %v", err)
	}
	// Signing in with the passkey still works, and is not a sign-up.
	login, _ := s.BeginPasskeySignIn(ctx)
	if again, err := s.FinishPasskey(ctx, login.SessionID, phone.get(t, login.Options)); err != nil || again.Created || again.UserID != session.UserID {
		t.Fatalf("sign-in: %v %+v", err, again)
	}

	// An expired code admits nobody.
	expired, _ := f.admissionCode(time.Hour)
	if _, err := f.pool.Exec(ctx, `UPDATE admission_codes SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{AdmissionCode: expired}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired code: %v", err)
	}
}

func TestAdmissionCodeByMagicLinkAndProvider(t *testing.T) {
	f := setup(t)
	mailer := &fakeMailer{sent: make(chan string, 16)}
	verifier := fakeVerifier{claims: map[string]oidc.Claims{}}
	s, _ := f.signIn(map[string]TokenVerifier{"google": verifier}, mailer, nil)
	ctx := t.Context()
	const base = "https://duongondro.app/m#"
	token := func() string {
		select {
		case last := <-mailer.sent:
			return last[strings.LastIndexAny(last, "/#")+1:]
		case <-time.After(5 * time.Second):
			t.Fatal("no mail was sent")
			return ""
		}
	}

	// Two links requested with one code, for two addresses: the code admits one.
	code, _ := f.admissionCode(time.Hour)
	if err := s.RequestMagicLink(ctx, "cy@example.com", &SignUpProof{AdmissionCode: code}, base); err != nil {
		t.Fatal(err)
	}
	first := token()
	if err := s.RequestMagicLink(ctx, "di@example.com", &SignUpProof{AdmissionCode: code}, base); err != nil {
		t.Fatal(err)
	}
	second := token()
	created, err := s.RedeemMagicLink(ctx, first)
	if err != nil || !created.Created {
		t.Fatalf("sign-up by link with a code: %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("one code admitted two accounts: %v", err)
	}
	if err := s.RequestMagicLink(ctx, "di@example.com", &SignUpProof{AdmissionCode: code}, base); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spent code requested a link: %v", err)
	}

	// Google, with a fresh code.
	code, _ = f.admissionCode(time.Hour)
	nonce, _ := s.NewNonce(ctx)
	verifier.claims["tok"] = oidc.Claims{Subject: "g-cy", Nonce: nonce}
	viaGoogle, err := s.ProviderSignIn(ctx, "google", "tok", nonce, "", &SignUpProof{AdmissionCode: code})
	if err != nil || !viaGoogle.Created {
		t.Fatalf("sign-up with Google and a code: %v", err)
	}
	var spent int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM admission_codes WHERE code_hash = $1 AND used_by = $2`,
		sha(NormalizeCode(code)), viaGoogle.UserID).Scan(&spent)
	if spent != 1 {
		t.Fatal("the Google sign-up did not spend the code")
	}
}

func sha(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
