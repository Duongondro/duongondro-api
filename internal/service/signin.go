package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/repository"
)

// SignIn holds the sign-in methods (design: From CodeShare › Sign-in). Three rules
// hold across them:
//
//   - An account is created only with a valid invitation or an unused admission
//     code: every method can sign in, none can sign up without one.
//   - Signing in never grants keys: a new device still enrols from an existing one
//     or the recovery code.
//   - Linking is explicit: a method is added to an account only from a signed-in
//     session, never because an e-mail address matches.
type SignIn struct {
	pool   *pgxpool.Pool
	q      *db.Queries
	auth   *auth.Service
	social *Social
	web    *webauthn.WebAuthn
	oidc   map[string]TokenVerifier
	mailer Mailer
	apple  AppleRevoker
	now    func() time.Time
}

// SignInConfig configures the sign-in methods. RPID is the passkey relying party
// (duongondro.app); RPOrigins the origins clients assert: https://duongondro.app for
// iOS, and android:apk-key-hash:… for the Android app.
type SignInConfig struct {
	RPID      string
	RPOrigins []string
	// Verifiers of ID tokens by provider ("apple", "google"); a provider without one
	// is answered 400 "not configured".
	Verifiers map[string]TokenVerifier
	Mailer    Mailer
	Apple     AppleRevoker
}

func NewSignIn(pool *pgxpool.Pool, a *auth.Service, social *Social, cfg SignInConfig) (*SignIn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Duongöndro",
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	s := &SignIn{pool: pool, q: db.New(pool), auth: a, social: social, web: web, oidc: cfg.Verifiers,
		mailer: cfg.Mailer, apple: cfg.Apple, now: time.Now}
	if s.oidc == nil {
		s.oidc = map[string]TokenVerifier{}
	}
	return s, nil
}

// Session is what every sign-in ends in.
type Session struct {
	Token   string
	UserID  uuid.UUID
	Created bool // a new account, made with an invitation or admission code
}

// InviteProof is the invitation a sign-up presents: its id and auth.
type InviteProof struct {
	ID   string
	Auth []byte
}

// ErrNoAccount answers a sign-in by a method no account uses, without an invite or
// admission code to create one: the app then asks for an invitation.
var ErrNoAccount = errors.New("no account uses this sign-in; an invitation is needed to create one")

// createAccount makes a user (with id, when given) inside the caller's transaction:
// a child of the inviter in the invite tree when g is an invite, a root (no inviter,
// no friendship) when it is an admission code, which it spends. It locks the invite
// or code and checks it is still live, so a revocation, the inviter's purge or
// another sign-up with the same code since the first check stops the sign-up
// (ErrNotFound) rather than slipping through.
func createAccount(ctx context.Context, q *db.Queries, g gate, id *uuid.UUID) (db.User, error) {
	var inviter *uuid.UUID
	switch {
	case g.inviteID != nil:
		inv, err := q.LockInvite(ctx, *g.inviteID)
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrNotFound
		} else if err != nil {
			return db.User{}, err
		}
		if inv.RevokedAt != nil || !inv.ExpiresAt.After(time.Now()) {
			return db.User{}, ErrNotFound
		}
		inviter = &inv.InviterID
	case g.admissionID != nil:
		if err := spendAdmission(ctx, q, *g.admissionID); err != nil {
			return db.User{}, err
		}
	default:
		return db.User{}, ErrNoAccount
	}
	var user db.User
	var err error
	if id != nil {
		user, err = q.CreateUserWithID(ctx, *id)
	} else {
		user, err = q.CreateUser(ctx)
	}
	if err != nil {
		return db.User{}, err
	}
	if g.admissionID != nil {
		if err := q.UseAdmissionCode(ctx, db.UseAdmissionCodeParams{ID: *g.admissionID, UsedBy: &user.ID}); err != nil {
			return db.User{}, err
		}
	}
	if err := q.CreateInviteNode(ctx, db.CreateInviteNodeParams{UserID: &user.ID, InviterID: inviter}); err != nil {
		return db.User{}, err
	}
	return user, nil
}

func (s *SignIn) session(ctx context.Context, userID uuid.UUID, created bool) (Session, error) {
	token, err := s.auth.NewSession(ctx, userID)
	return Session{Token: token, UserID: userID, Created: created}, err
}

// --- Passkeys ------------------------------------------------------------------

// passkeyUser adapts an account (or one about to be created) to webauthn.User. The
// user handle is the account id, so a discoverable sign-in finds the account.
type passkeyUser struct {
	id          uuid.UUID
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id[:] }
func (u *passkeyUser) WebAuthnName() string                       { return "Duongöndro" }
func (u *passkeyUser) WebAuthnDisplayName() string                { return "Duongöndro" }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *SignIn) loadPasskeyUser(ctx context.Context, q *db.Queries, id uuid.UUID) (*passkeyUser, error) {
	rows, err := q.ListCredentials(ctx, id)
	if err != nil {
		return nil, err
	}
	u := &passkeyUser{id: id, credentials: make([]webauthn.Credential, len(rows))}
	for i, r := range rows {
		if err := json.Unmarshal(r.Data, &u.credentials[i]); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// Ceremony is a WebAuthn ceremony to complete on the phone.
type Ceremony struct {
	SessionID uuid.UUID
	Options   any
}

func (s *SignIn) saveCeremony(ctx context.Context, data *webauthn.SessionData, userID *uuid.UUID, g gate) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.UUID{}, err
	}
	if _, err := s.q.PurgeExpiredWebauthnSessions(ctx); err != nil {
		return uuid.UUID{}, err
	}
	return s.q.CreateWebauthnSession(ctx, db.CreateWebauthnSessionParams{Data: raw, UserID: userID, InviteID: g.inviteID,
		AdmissionID: g.admissionID})
}

func (s *SignIn) consumeCeremony(ctx context.Context, id uuid.UUID) (db.WebauthnSession, webauthn.SessionData, error) {
	var data webauthn.SessionData
	row, err := s.q.ConsumeWebauthnSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, data, invalid("the passkey ceremony expired or is unknown; start again")
	} else if err != nil {
		return row, data, err
	}
	return row, data, json.Unmarshal(row.Data, &data)
}

// BeginPasskeySignUp starts creating an account with a passkey; the invitation or
// admission code is checked now and again when the ceremony finishes.
func (s *SignIn) BeginPasskeySignUp(ctx context.Context, proof SignUpProof) (Ceremony, error) {
	g, err := s.checkProof(ctx, proof)
	if err != nil {
		return Ceremony{}, err
	}
	id := uuid.NewV7()
	options, data, err := s.web.BeginRegistration(&passkeyUser{id: id},
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		return Ceremony{}, err
	}
	sid, err := s.saveCeremony(ctx, data, &id, g)
	return Ceremony{SessionID: sid, Options: options}, err
}

// BeginPasskeyAdd starts adding a passkey to a signed-in account.
func (s *SignIn) BeginPasskeyAdd(ctx context.Context, userID uuid.UUID) (Ceremony, error) {
	u, err := s.loadPasskeyUser(ctx, s.q, userID)
	if err != nil {
		return Ceremony{}, err
	}
	exclude := make([]protocol.CredentialDescriptor, len(u.credentials))
	for i, c := range u.credentials {
		exclude[i] = c.Descriptor()
	}
	options, data, err := s.web.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(exclude))
	if err != nil {
		return Ceremony{}, err
	}
	sid, err := s.saveCeremony(ctx, data, &userID, gate{})
	return Ceremony{SessionID: sid, Options: options}, err
}

// FinishPasskeyRegistration completes a sign-up (creating the account and signing
// in) or, with signedIn set, adds the passkey to that account.
func (s *SignIn) FinishPasskeyRegistration(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, signedIn *uuid.UUID) (Session, error) {
	row, data, err := s.consumeCeremony(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	return s.finishRegistration(ctx, row, data, credential, signedIn)
}

// FinishPasskey completes whichever signed-out ceremony sessionID began: a sign-up
// or a sign-in.
func (s *SignIn) FinishPasskey(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage) (Session, error) {
	row, data, err := s.consumeCeremony(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	if ceremonyGate(row) != (gate{}) {
		return s.finishRegistration(ctx, row, data, credential, nil)
	}
	return s.finishSignIn(ctx, row, data, credential)
}

func (s *SignIn) finishRegistration(ctx context.Context, row db.WebauthnSession, data webauthn.SessionData, credential json.RawMessage, signedIn *uuid.UUID) (Session, error) {
	g := ceremonyGate(row)
	signUp := g != (gate{})
	if row.UserID == nil || signUp == (signedIn != nil) || (signedIn != nil && *signedIn != *row.UserID) {
		return Session{}, invalid("this passkey ceremony belongs to another flow")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credential)
	if err != nil {
		return Session{}, invalid("the passkey response is malformed: %v", err)
	}
	u, err := s.loadPasskeyUser(ctx, s.q, *row.UserID)
	if err != nil {
		return Session{}, err
	}
	cred, err := s.web.CreateCredential(u, data, parsed)
	if err != nil {
		return Session{}, invalid("the passkey was not accepted: %v", err)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return Session{}, err
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if signUp {
			// The invite may have been revoked or expired, or the admission code spent,
			// since the ceremony began.
			if _, err := createAccount(ctx, q, g, row.UserID); err != nil {
				return err
			}
		}
		return q.CreateCredential(ctx, db.CreateCredentialParams{ID: cred.ID, UserID: *row.UserID, Data: raw})
	})
	if repository.IsUniqueViolation(err, "credentials_pkey") {
		return Session{}, conflict("this passkey is already registered")
	} else if err != nil {
		return Session{}, err
	}
	if !signUp {
		return Session{UserID: *row.UserID}, nil
	}
	return s.session(ctx, *row.UserID, true)
}

// ceremonyGate is the invite or admission code a sign-up ceremony began with; zero
// for a sign-in or for adding a passkey.
func ceremonyGate(row db.WebauthnSession) gate {
	return gate{inviteID: row.InviteID, admissionID: row.AdmissionID}
}

// BeginPasskeySignIn starts a discoverable sign-in: the phone offers its passkeys.
func (s *SignIn) BeginPasskeySignIn(ctx context.Context) (Ceremony, error) {
	options, data, err := s.web.BeginDiscoverableLogin()
	if err != nil {
		return Ceremony{}, err
	}
	sid, err := s.saveCeremony(ctx, data, nil, gate{})
	return Ceremony{SessionID: sid, Options: options}, err
}

func (s *SignIn) FinishPasskeySignIn(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage) (Session, error) {
	row, data, err := s.consumeCeremony(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	return s.finishSignIn(ctx, row, data, credential)
}

func (s *SignIn) finishSignIn(ctx context.Context, row db.WebauthnSession, data webauthn.SessionData, credential json.RawMessage) (Session, error) {
	if row.UserID != nil || ceremonyGate(row) != (gate{}) {
		return Session{}, invalid("this passkey ceremony belongs to another flow")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credential)
	if err != nil {
		return Session{}, invalid("the passkey response is malformed: %v", err)
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := uuidFromBytes(userHandle)
		if err != nil {
			return nil, err
		}
		return s.loadPasskeyUser(ctx, s.q, id)
	}
	user, cred, err := s.web.ValidatePasskeyLogin(handler, data, parsed)
	if err != nil {
		return Session{}, invalid("the passkey was not accepted: %v", err)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return Session{}, err
	}
	if err := s.q.UpdateCredential(ctx, db.UpdateCredentialParams{ID: cred.ID, Data: raw}); err != nil {
		return Session{}, err
	}
	id, err := uuidFromBytes(user.WebAuthnID())
	if err != nil {
		return Session{}, err
	}
	return s.session(ctx, id, false)
}

// uuidFromBytes reads a 16-byte user handle back into an account id.
func uuidFromBytes(b []byte) (uuid.UUID, error) {
	var id uuid.UUID
	if len(b) != len(id) {
		return id, fmt.Errorf("a user handle is %d bytes, not %d", len(b), len(id))
	}
	copy(id[:], b)
	return id, nil
}
