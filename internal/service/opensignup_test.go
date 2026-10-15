package service

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/oidc"
)

// signInWith is f.signIn with Google and a mailer.
func (f *fixture) signInWith() (*SignIn, *Social, fakeVerifier, *fakeMailer) {
	f.t.Helper()
	social := NewSocial(f.pool, f.keys)
	verifier := fakeVerifier{claims: map[string]oidc.Claims{}}
	mailer := &fakeMailer{sent: make(chan string, 16)}
	s, err := NewSignIn(f.pool, f.keys, auth.New(f.pool, f.keys), social, SignInConfig{RPID: testRPID, RPOrigins: []string{testOrigin},
		Verifiers: map[string]TokenVerifier{"google": verifier}, Mailer: mailer})
	if err != nil {
		f.t.Fatal(err)
	}
	return s, social, verifier, mailer
}

func from(ctx context.Context, addr string) context.Context { return WithClientAddress(ctx, addr) }

// openProof is what a 0.4 app sends to sign up without an invitation.
var openProof = SignUpProof{SignUp: true, Consent: true}

// isRoot reports whether the account is a root of the invite tree without friends.
func (f *fixture) isRoot(social *Social, id uuid.UUID) bool {
	f.t.Helper()
	var parent *string
	if err := f.pool.QueryRow(f.t.Context(), `SELECT parent_id::text FROM invite_tree WHERE user_id = $1`, id).Scan(&parent); err != nil {
		f.t.Fatalf("invite tree: %v", err)
	}
	friends, _ := social.Friends(f.t.Context(), id)
	return parent == nil && len(friends) == 0
}

func (f *fixture) passkeySignUp(s *SignIn, ctx context.Context, proof SignUpProof) (Session, error) {
	f.t.Helper()
	c, err := s.BeginPasskeySignUp(ctx, proof, SignUpProfile{})
	if err != nil {
		return Session{}, err
	}
	return s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(f.t, c.Options))
}

// Sign-up needs no invitation and no configuration: the plain sign-in, as every
// other test builds it, makes an account for a request marked as a sign-up.
// Invitations and admission codes work as before, with or without the flag.
func TestSignUpWithoutCodeNeedsNoConfiguration(t *testing.T) {
	f := setup(t)
	mailer := &fakeMailer{sent: make(chan string, 16)}
	s, social := f.signIn(nil, mailer, nil)
	ctx := from(t.Context(), "198.51.100.7")

	session, err := f.passkeySignUp(s, ctx, openProof)
	if err != nil || !session.Created || !f.isRoot(social, session.UserID) {
		t.Fatalf("passkey sign-up without a code: %v %+v", err, session)
	}
	if err := s.RequestMagicLink(ctx, "new@example.com", &openProof, "https://duongondro.app/m#"); err != nil {
		t.Fatal(err)
	}
	_, token := mailOf(t, mailer)
	if viaMail, err := s.RedeemMagicLink(ctx, token); err != nil || !viaMail.Created || !f.isRoot(social, viaMail.UserID) {
		t.Fatalf("magic-link sign-up without a code: %v", err)
	}
	// Without the flag and without a code it is no sign-up, as before.
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{}, SignUpProfile{}); !isValidation(err) {
		t.Fatalf("passkey sign-up without anything: %v", err)
	}

	inviter := f.member()
	invAuth := f.invite(social, inviter, "C0DEDXXX")
	session, err = f.passkeySignUp(s, ctx, SignUpProof{Invite: &InviteProof{ID: "C0DEDXXX", Auth: invAuth}})
	if err != nil || !session.Created || f.isRoot(social, session.UserID) {
		t.Fatalf("invited sign-up without the flag: %v %+v", err, session)
	}
	session, err = f.passkeySignUp(s, ctx, SignUpProof{Invite: &InviteProof{ID: "C0DEDXXX", Auth: invAuth}, SignUp: true, Consent: true})
	if err != nil || !session.Created {
		t.Fatalf("invited sign-up with the flag: %v", err)
	}
	code, _ := f.admissionCode(time.Hour)
	session, err = f.passkeySignUp(s, ctx, SignUpProof{AdmissionCode: code})
	if err != nil || !session.Created || !f.isRoot(social, session.UserID) {
		t.Fatalf("admission code without the flag: %v", err)
	}
	code, _ = f.admissionCode(time.Hour)
	session, err = f.passkeySignUp(s, ctx, SignUpProof{AdmissionCode: code, SignUp: true, Consent: true})
	if err != nil || !session.Created || !f.isRoot(social, session.UserID) {
		t.Fatalf("admission code with the flag: %v", err)
	}
	// The flag without consent is refused, invitation or not.
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{Invite: &InviteProof{ID: "C0DEDXXX", Auth: invAuth}, SignUp: true}, SignUpProfile{}); !isValidation(err) {
		t.Fatalf("flag without consent: %v", err)
	}
}

func TestOpenSignUpOn(t *testing.T) {
	f := setup(t)
	s, social, verifier, mailer := f.signInWith()
	ctx := from(t.Context(), "198.51.100.8")
	var before int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&before)

	// Consent comes first: nothing is begun or created without it.
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{SignUp: true}, SignUpProfile{}); !isValidation(err) {
		t.Fatalf("open sign-up without consent: %v", err)
	}
	nonce, _ := s.NewNonce(ctx)
	verifier.claims["tok-noconsent"] = oidc.Claims{Subject: "g-noconsent", Nonce: nonce}
	if _, err := s.ProviderSignIn(ctx, "google", "tok-noconsent", nonce, "", &SignUpProof{SignUp: true}); !isValidation(err) {
		t.Fatalf("open Google sign-up without consent: %v", err)
	}
	if err := s.RequestMagicLink(ctx, "noconsent@example.com", &SignUpProof{SignUp: true}, "https://duongondro.app/m#"); !isValidation(err) {
		t.Fatalf("open magic link without consent: %v", err)
	}
	var after int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&after)
	if after != before {
		t.Fatalf("%d accounts made without consent", after-before)
	}
	// Without the flag and without an invitation, still refused as before.
	if _, err := s.BeginPasskeySignUp(ctx, SignUpProof{}, SignUpProfile{}); !isValidation(err) {
		t.Fatalf("passkey sign-up without anything: %v", err)
	}
	nonce, _ = s.NewNonce(ctx)
	verifier.claims["tok-noflag"] = oidc.Claims{Subject: "g-noflag", Nonce: nonce}
	if _, err := s.ProviderSignIn(ctx, "google", "tok-noflag", nonce, "", nil); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("Google without the flag: %v", err)
	}

	// Passkey: a root of the invite tree, no friends; signing in afterwards is no sign-up.
	phone := newAuthenticator()
	c, err := s.BeginPasskeySignUp(ctx, openProof, SignUpProfile{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.FinishPasskey(ctx, c.SessionID, phone.create(t, c.Options))
	if err != nil || !session.Created || !f.isRoot(social, session.UserID) {
		t.Fatalf("open passkey sign-up: %v %+v", err, session)
	}
	login, _ := s.BeginPasskeySignIn(ctx)
	if again, err := s.FinishPasskey(ctx, login.SessionID, phone.get(t, login.Options)); err != nil || again.Created || again.UserID != session.UserID {
		t.Fatalf("sign-in after an open sign-up: %v %+v", err, again)
	}
	// Adding a passkey is not a sign-up and cannot be finished as one.
	add, _ := s.BeginPasskeyAdd(ctx, session.UserID)
	if _, err := s.FinishPasskey(ctx, add.SessionID, newAuthenticator().create(t, add.Options)); !isValidation(err) {
		t.Fatalf("an add-passkey ceremony finished signed out: %v", err)
	}

	// Google: creates an account; the same account later just signs in, flag or not.
	nonce, _ = s.NewNonce(ctx)
	verifier.claims["tok-open"] = oidc.Claims{Subject: "g-open", Nonce: nonce}
	viaGoogle, err := s.ProviderSignIn(ctx, "google", "tok-open", nonce, "", &openProof)
	if err != nil || !viaGoogle.Created || !f.isRoot(social, viaGoogle.UserID) {
		t.Fatalf("open Google sign-up: %v", err)
	}
	nonce, _ = s.NewNonce(ctx)
	verifier.claims["tok-open2"] = oidc.Claims{Subject: "g-open", Nonce: nonce}
	if again, err := s.ProviderSignIn(ctx, "google", "tok-open2", nonce, "", &openProof); err != nil || again.Created || again.UserID != viaGoogle.UserID {
		t.Fatalf("Google sign-in with the flag: %v %+v", err, again)
	}

	// Magic link: the mail goes to a new address, and the link makes the account.
	if err := s.RequestMagicLink(ctx, "Eve@Example.com", &openProof, "https://duongondro.app/m#"); err != nil {
		t.Fatal(err)
	}
	_, token := mailOf(t, mailer)
	viaMail, err := s.RedeemMagicLink(ctx, token)
	if err != nil || !viaMail.Created || !f.isRoot(social, viaMail.UserID) {
		t.Fatalf("open magic-link sign-up: %v", err)
	}
	// A plain link request for an unknown address still mails nothing.
	if err := s.RequestMagicLink(ctx, "quiet@example.com", nil, "https://duongondro.app/m#"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-mailer.sent:
		t.Fatalf("mail without the flag to an unknown address: %s", m)
	case <-time.After(200 * time.Millisecond):
	}

	// A friend's invitation with the flag still makes the account the inviter's
	// child, and redeeming it makes the two friends.
	inviter := f.member()
	invAuth := f.invite(social, inviter, "FR1ENDXX")
	invited, err := f.passkeySignUp(s, ctx, SignUpProof{Invite: &InviteProof{ID: "FR1ENDXX", Auth: invAuth}, SignUp: true, Consent: true})
	if err != nil || !invited.Created || f.isRoot(social, invited.UserID) {
		t.Fatalf("invited sign-up with open sign-up on: %v", err)
	}
	u, err := f.keys.User(f.q.GetUser(ctx, invited.UserID))
	if err != nil {
		t.Fatal(err)
	}
	u, priv := f.withIdentity(u)
	p, sg := acceptance(member{User: u, identity: priv}, "FR1ENDXX")
	if _, err := social.Redeem(ctx, u, "FR1ENDXX", invAuth, p, sg); err != nil {
		t.Fatal(err)
	}
	if friends, _ := social.Friends(ctx, inviter.ID); len(friends) != 1 || friends[0].ID != invited.UserID {
		t.Fatalf("inviter's friends: %+v", friends)
	}
	// An admission code is still spent when given.
	code, normalized := f.admissionCode(time.Hour)
	if s, err := f.passkeySignUp(s, ctx, SignUpProof{AdmissionCode: code}); err != nil || !f.isRoot(social, s.UserID) {
		t.Fatalf("admission code with open sign-up on: %v", err)
	}
	var used int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM admission_codes WHERE code_hash = $1 AND used_at IS NOT NULL`, sha(normalized)).Scan(&used)
	if used != 1 {
		t.Fatal("the admission code was not spent")
	}
}

func TestOpenSignUpRateLimit(t *testing.T) {
	f := setup(t)
	s, _, verifier, mailer := f.signInWith()
	now := time.Now()
	s.SetOpenSignUpClock(func() time.Time { return now })
	ctx := from(t.Context(), "203.0.113.9")

	// Ceremonies that never finish do not count.
	for range 2 * OpenSignUpLimit {
		if _, err := s.BeginPasskeySignUp(ctx, openProof, SignUpProfile{}); err != nil {
			t.Fatalf("an abandoned ceremony counted: %v", err)
		}
	}
	// A ceremony begun under the limit is refused at the end once the limit is reached.
	late, err := s.BeginPasskeySignUp(ctx, openProof, SignUpProfile{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range OpenSignUpLimit - 1 {
		if _, err := f.passkeySignUp(s, ctx, openProof); err != nil {
			t.Fatalf("sign-up %d: %v", i+1, err)
		}
	}
	nonce, _ := s.NewNonce(ctx)
	verifier.claims["fifth"] = oidc.Claims{Subject: "g-fifth", Nonce: nonce}
	if _, err := s.ProviderSignIn(ctx, "google", "fifth", nonce, "", &openProof); err != nil {
		t.Fatalf("fifth sign-up, by Google: %v", err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, openProof, SignUpProfile{}); !errors.Is(err, ErrSignUpRateLimited) {
		t.Fatalf("sixth passkey sign-up began: %v", err)
	}
	if _, err := s.FinishPasskey(ctx, late.SessionID, newAuthenticator().create(t, late.Options)); !errors.Is(err, ErrSignUpRateLimited) {
		t.Fatalf("sixth passkey sign-up finished: %v", err)
	}
	nonce, _ = s.NewNonce(ctx)
	verifier.claims["sixth"] = oidc.Claims{Subject: "g-sixth", Nonce: nonce}
	if _, err := s.ProviderSignIn(ctx, "google", "sixth", nonce, "", &openProof); !errors.Is(err, ErrSignUpRateLimited) {
		t.Fatalf("sixth Google sign-up: %v", err)
	}

	// Not counted: sign-ups with an invitation or code, e-mail sign-ups, other addresses.
	code, _ := f.admissionCode(time.Hour)
	if _, err := f.passkeySignUp(s, ctx, SignUpProof{AdmissionCode: code, SignUp: true, Consent: true}); err != nil {
		t.Fatalf("an admission code over the open limit: %v", err)
	}
	if err := s.RequestMagicLink(ctx, "over@example.com", &openProof, "https://duongondro.app/m#"); err != nil {
		t.Fatal(err)
	}
	_, token := mailOf(t, mailer)
	if viaMail, err := s.RedeemMagicLink(ctx, token); err != nil || !viaMail.Created {
		t.Fatalf("an e-mail sign-up over the open limit: %v", err)
	}
	if _, err := f.passkeySignUp(s, from(t.Context(), "203.0.113.10"), openProof); err != nil {
		t.Fatalf("another address: %v", err)
	}

	// An hour later the address may sign up again.
	now = now.Add(OpenSignUpWindow)
	if _, err := f.passkeySignUp(s, ctx, openProof); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestAddressLimiterForgets(t *testing.T) {
	l := newAddressLimiter(2, time.Hour)
	now := time.Now()
	l.now = func() time.Time { return now }
	for _, addr := range []string{"a", "b", "c"} {
		if !l.take(addr) {
			t.Fatal(addr)
		}
	}
	if !l.take("a") || l.take("a") || l.allowed("a") {
		t.Fatal("limit of 2 not held")
	}
	now = now.Add(time.Hour)
	if !l.allowed("z") || len(l.seen) != 0 {
		t.Fatalf("%d addresses kept past the window", len(l.seen))
	}
}

// Open magic-link requests count per client address when asked for, mailed or not:
// the 429 says nothing about the address.
func TestOpenSignUpMailLimit(t *testing.T) {
	f := setup(t)
	s, _, _, mailer := f.signInWith()
	ctx := from(t.Context(), "198.51.100.20")
	const base = "https://duongondro.app/m#"

	// One address already has an account; its requests count like any other.
	if err := s.RequestMagicLink(ctx, "known@example.com", &openProof, base); err != nil {
		t.Fatal(err)
	}
	_, token := mailOf(t, mailer)
	if _, err := s.RedeemMagicLink(ctx, token); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < OpenSignUpMailLimit; i++ {
		if err := s.RequestMagicLink(ctx, "user"+string(rune('a'+i))+"@example.com", &openProof, base); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		mailOf(t, mailer)
	}
	for _, addr := range []string{"new@example.com", "known@example.com"} {
		if err := s.RequestMagicLink(ctx, addr, &openProof, base); !errors.Is(err, ErrSignUpMailRateLimited) {
			t.Fatalf("%s over the limit: %v", addr, err)
		}
	}
	// Not counted, nor refused: a plain sign-in request, one with a code, another address.
	if err := s.RequestMagicLink(ctx, "known@example.com", nil, base); err != nil {
		t.Fatalf("sign-in link over the open limit: %v", err)
	}
	mailOf(t, mailer)
	code, _ := f.admissionCode(time.Hour)
	if err := s.RequestMagicLink(ctx, "coded@example.com", &SignUpProof{AdmissionCode: code, SignUp: true, Consent: true}, base); err != nil {
		t.Fatalf("admission code over the open limit: %v", err)
	}
	mailOf(t, mailer)
	if err := s.RequestMagicLink(from(t.Context(), "198.51.100.21"), "elsewhere@example.com", &openProof, base); err != nil {
		t.Fatalf("another address: %v", err)
	}
	mailOf(t, mailer)
	// Consent and the closed switch are answered before a slot is taken.
	if err := s.RequestMagicLink(from(t.Context(), "198.51.100.22"), "x@example.com", &SignUpProof{SignUp: true}, base); !isValidation(err) {
		t.Fatal(err)
	}
}

// IPv4 counts per address, IPv6 per /64.
func TestLimitKey(t *testing.T) {
	for addr, want := range map[string]string{
		"198.51.100.7":                     "198.51.100.7",
		"::ffff:198.51.100.7":              "198.51.100.7",
		"2001:db8:1:2:aaaa:bbbb:cccc:dddd": "2001:db8:1:2::/64",
		"2001:db8:1:2::1":                  "2001:db8:1:2::/64",
		"fe80::1%en0":                      "fe80::/64",
		"not an address":                   "not an address",
	} {
		if got := limitKey(addr); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
	l := newAddressLimiter(1, time.Hour)
	if !l.take("2001:db8:1:2::1") || l.allowed("2001:db8:1:2:ffff::9") {
		t.Fatal("two addresses in one /64 counted apart")
	}
	if !l.allowed("2001:db8:1:3::1") || !l.allowed("198.51.100.8") {
		t.Fatal("another /64 or IPv4 address shares the count")
	}
}
