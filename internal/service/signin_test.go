package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/oidc"
)

const (
	testRPID   = "duongondro.app"
	testOrigin = "https://duongondro.app"
)

// authenticator is a software passkey: what a phone's platform authenticator does,
// reduced to what the server checks (none attestation, ES256, user verification).
type authenticator struct {
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	count      uint32
}

func newAuthenticator() *authenticator {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &authenticator{key: key, credID: random(16)}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func clientData(typ string, challenge string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": testOrigin})
	return raw
}

func (a *authenticator) authData(withCredential bool) []byte {
	rpHash := sha256.Sum256([]byte(testRPID))
	flags := byte(0x01 | 0x04) // user present, user verified
	if withCredential {
		flags |= 0x40
	}
	a.count++
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if withCredential {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		pub, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
			-2: a.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: a.key.PublicKey.Y.FillBytes(make([]byte, 32))})
		out = append(out, pub...)
	}
	return out
}

// create answers a registration ceremony's options.
func (a *authenticator) create(t *testing.T, options any) json.RawMessage {
	creation := options.(*protocol.CredentialCreation)
	a.userHandle = creation.Response.User.ID.(protocol.URLEncodedBase64)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	raw, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData("webauthn.create", b64(creation.Response.Challenge))),
			"attestationObject": b64(att),
		},
	})
	return raw
}

// get answers a sign-in ceremony's options.
func (a *authenticator) get(t *testing.T, options any) json.RawMessage {
	assertion := options.(*protocol.CredentialAssertion)
	cd := clientData("webauthn.get", b64(assertion.Response.Challenge))
	ad := a.authData(false)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	raw, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig), "userHandle": b64(a.userHandle),
		},
	})
	return raw
}

type fakeVerifier struct{ claims map[string]oidc.Claims }

func (v fakeVerifier) Verify(_ context.Context, raw string) (oidc.Claims, error) {
	c, ok := v.claims[raw]
	if !ok {
		return oidc.Claims{}, oidc.ErrInvalidToken
	}
	return c, nil
}

type fakeMailer struct{ sent []string }

func (m *fakeMailer) SendMagicLink(_ context.Context, to, link string) error {
	m.sent = append(m.sent, to+" "+link)
	return nil
}

type fakeApple struct{ revoked []string }

func (a *fakeApple) Exchange(_ context.Context, code string) (string, error) {
	return "refresh-" + code, nil
}
func (a *fakeApple) Revoke(_ context.Context, token string) error {
	a.revoked = append(a.revoked, token)
	return nil
}

func (f *fixture) signIn(verifiers map[string]TokenVerifier, mailer Mailer, apple AppleRevoker) (*SignIn, *Social) {
	social := NewSocial(f.pool)
	s, err := NewSignIn(f.pool, auth.New(f.pool), social, SignInConfig{RPID: testRPID, RPOrigins: []string{testOrigin},
		Verifiers: verifiers, Mailer: mailer, Apple: apple})
	if err != nil {
		f.t.Fatal(err)
	}
	return s, social
}

func TestPasskeys(t *testing.T) {
	f := setup(t)
	s, social := f.signIn(nil, nil, nil)
	ctx := t.Context()
	inviter := f.member()
	auth := f.invite(social, inviter, "P4SSK3YS")

	if _, err := s.BeginPasskeySignUp(ctx, InviteProof{ID: "P4SSK3YS", Auth: random(32)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sign-up without the invite's auth: %v", err)
	}
	phone := newAuthenticator()
	ceremony, err := s.BeginPasskeySignUp(ctx, InviteProof{ID: "P4SSK3YS", Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.FinishPasskeyRegistration(ctx, ceremony.SessionID, phone.create(t, ceremony.Options), nil)
	if err != nil || !session.Created || session.Token == "" {
		t.Fatalf("sign-up: %v %+v", err, session)
	}
	// A ceremony is single use.
	if _, err := s.FinishPasskeyRegistration(ctx, ceremony.SessionID, phone.create(t, ceremony.Options), nil); !isValidation(err) {
		t.Fatalf("ceremony reused: %v", err)
	}
	// The new account sits under the inviter in the invite tree.
	var parentUser string
	if err := f.pool.QueryRow(ctx, `SELECT p.user_id::text FROM invite_tree c JOIN invite_tree p ON p.node_id = c.parent_id
		WHERE c.user_id = $1`, session.UserID).Scan(&parentUser); err != nil || parentUser != inviter.ID.String() {
		t.Fatalf("invite tree: %v %s", err, parentUser)
	}

	login, err := s.BeginPasskeySignIn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.FinishPasskeySignIn(ctx, login.SessionID, phone.get(t, login.Options))
	if err != nil || again.UserID != session.UserID || again.Created {
		t.Fatalf("sign-in: %v %+v", err, again)
	}
	stranger := newAuthenticator()
	stranger.userHandle = phone.userHandle
	login, _ = s.BeginPasskeySignIn(ctx)
	if _, err := s.FinishPasskeySignIn(ctx, login.SessionID, stranger.get(t, login.Options)); !isValidation(err) {
		t.Fatalf("an unregistered passkey signed in: %v", err)
	}

	// A second passkey, added from the signed-in account.
	tablet := newAuthenticator()
	add, err := s.BeginPasskeyAdd(ctx, session.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinishPasskeyRegistration(ctx, add.SessionID, tablet.create(t, add.Options), &inviter.ID); !isValidation(err) {
		t.Fatalf("finishing another account's ceremony: %v", err)
	}
	add, _ = s.BeginPasskeyAdd(ctx, session.UserID)
	if _, err := s.FinishPasskeyRegistration(ctx, add.SessionID, tablet.create(t, add.Options), &session.UserID); err != nil {
		t.Fatalf("add a passkey: %v", err)
	}
	creds, _ := f.q.ListCredentials(ctx, session.UserID)
	if len(creds) != 2 {
		t.Fatalf("%d passkeys, want 2", len(creds))
	}
}

func TestProviders(t *testing.T) {
	f := setup(t)
	nonceHash := sha256.Sum256([]byte("raw-nonce"))
	verifier := fakeVerifier{claims: map[string]oidc.Claims{
		"apple-token":  {Subject: "001.ana", Email: "Ana@privaterelay.appleid.com", EmailVerified: true, Nonce: b64hex(nonceHash[:])},
		"google-token": {Subject: "g-ana", Nonce: "raw-nonce"},
	}}
	apple := &fakeApple{}
	s, social := f.signIn(map[string]TokenVerifier{"apple": verifier, "google": verifier}, nil, apple)
	ctx := t.Context()
	inviter := f.member()
	auth := f.invite(social, inviter, "APP1EGGG")

	if _, err := s.ProviderSignIn(ctx, "apple", "apple-token", "raw-nonce", "code", nil); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("sign-in without an account or invite: %v", err)
	}
	if _, err := s.ProviderSignIn(ctx, "apple", "apple-token", "other-nonce", "", &InviteProof{ID: "APP1EGGG", Auth: auth}); !isValidation(err) {
		t.Fatalf("a token for another sign-in: %v", err)
	}
	created, err := s.ProviderSignIn(ctx, "apple", "apple-token", "raw-nonce", "code", &InviteProof{ID: "APP1EGGG", Auth: auth})
	if err != nil || !created.Created {
		t.Fatalf("sign-up with Apple: %v", err)
	}
	again, err := s.ProviderSignIn(ctx, "apple", "apple-token", "raw-nonce", "", nil)
	if err != nil || again.UserID != created.UserID || again.Created {
		t.Fatalf("sign-in with Apple: %v", err)
	}
	if _, err := s.ProviderSignIn(ctx, "facebook", "x", "raw-nonce", "", nil); !isValidation(err) {
		t.Fatalf("unconfigured provider: %v", err)
	}

	// Google is linked explicitly from the signed-in account, then signs in to it.
	if err := s.LinkProvider(ctx, created.UserID, "google", "google-token", "raw-nonce", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkProvider(ctx, inviter.ID, "google", "google-token", "raw-nonce", ""); !isConflict(err) {
		t.Fatalf("linking an account already linked elsewhere: %v", err)
	}
	viaGoogle, err := s.ProviderSignIn(ctx, "google", "google-token", "raw-nonce", "", nil)
	if err != nil || viaGoogle.UserID != created.UserID {
		t.Fatalf("sign-in with Google: %v", err)
	}

	s.RevokeApple(ctx, created.UserID)
	if len(apple.revoked) != 1 || apple.revoked[0] != "refresh-code" {
		t.Fatalf("revoked %v", apple.revoked)
	}
}

func b64hex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = hexdigits[c>>4], hexdigits[c&15]
	}
	return string(out)
}

func TestMagicLinks(t *testing.T) {
	f := setup(t)
	mailer := &fakeMailer{}
	s, social := f.signIn(nil, mailer, nil)
	ctx := t.Context()
	inviter := f.member()
	auth := f.invite(social, inviter, "MAG1CK1N")
	token := func() string {
		last := mailer.sent[len(mailer.sent)-1]
		return last[strings.LastIndex(last, "/")+1:]
	}

	// No account and no invite: nothing is sent, and the answer gives nothing away.
	if err := s.RequestMagicLink(ctx, "nobody@example.com", nil, "https://duongondro.app/m/"); err != nil || len(mailer.sent) != 0 {
		t.Fatalf("unknown address: %v %v", err, mailer.sent)
	}
	if err := s.RequestMagicLink(ctx, "not an address", nil, "https://duongondro.app/m/"); !isValidation(err) {
		t.Fatalf("bad address: %v", err)
	}
	if err := s.RequestMagicLink(ctx, "Bo@Example.com", &InviteProof{ID: "MAG1CK1N", Auth: auth}, "https://duongondro.app/m/"); err != nil {
		t.Fatal(err)
	}
	created, err := s.RedeemMagicLink(ctx, token())
	if err != nil || !created.Created {
		t.Fatalf("sign-up by link: %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, token()); !isValidation(err) {
		t.Fatalf("a link used twice: %v", err)
	}

	// Now the address has an account: a link without an invite signs in.
	if err := s.RequestMagicLink(ctx, "bo@example.com", nil, "https://duongondro.app/m/"); err != nil {
		t.Fatal(err)
	}
	session, err := s.RedeemMagicLink(ctx, token())
	if err != nil || session.UserID != created.UserID || session.Created {
		t.Fatalf("sign-in by link: %v", err)
	}
	for i := 0; i < magicLinksPerWindow; i++ {
		_ = s.RequestMagicLink(ctx, "bo@example.com", nil, "https://duongondro.app/m/")
	}
	if err := s.RequestMagicLink(ctx, "bo@example.com", nil, "https://duongondro.app/m/"); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("too many links: %v", err)
	}
}
