package service

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/repository"
	"github.com/Duongondro/duongondro-api/internal/service/names"
)

// SignIn holds the sign-in methods (design: From CodeShare › Sign-in). Three rules
// hold across them:
//
//   - An account is created only by a request that is a sign-up: one marked as one
//     (signUp, opensignup.go), or one with a valid invitation or an unused admission
//     code. Every method can sign in.
//   - Signing in never grants keys: a new device still enrols from an existing one
//     or the recovery code.
//   - Linking is explicit: a method is added to an account only from a signed-in
//     session, never because an e-mail address matches.
type SignIn struct {
	pool   *pgxpool.Pool
	q      *db.Queries
	keys   *atrest.Keys
	auth   *auth.Service
	social *Social
	web    *webauthn.WebAuthn
	oidc   map[string]TokenVerifier
	mailer Mailer
	apple  AppleRevoker
	now    func() time.Time
	// codeKey keys the hashes of magic-link codes; random per process, never stored.
	codeKey []byte
	// openLimit counts accounts made with neither invitation nor admission code per
	// client address.
	openLimit *addressLimiter
	// openMailLimit counts open sign-up requests for a magic link per client
	// address, mailed or not.
	openMailLimit *addressLimiter
	// confirmLimit counts the e-mail confirmations each account asks for, by its id.
	confirmLimit *addressLimiter
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

func NewSignIn(pool *pgxpool.Pool, keys *atrest.Keys, a *auth.Service, social *Social, cfg SignInConfig) (*SignIn, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Duongöndro",
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	codeKey := make([]byte, 32)
	if _, err := rand.Read(codeKey); err != nil {
		return nil, err
	}
	s := &SignIn{pool: pool, q: db.New(pool), keys: keys, auth: a, social: social, web: web, oidc: cfg.Verifiers,
		mailer: cfg.Mailer, apple: cfg.Apple, now: time.Now, codeKey: codeKey,
		openLimit:     newAddressLimiter(OpenSignUpLimit, OpenSignUpWindow),
		openMailLimit: newAddressLimiter(OpenSignUpMailLimit, OpenSignUpWindow),
		confirmLimit:  newAddressLimiter(EmailConfirmationLimit, EmailConfirmationWindow)}
	if s.oidc == nil {
		s.oidc = map[string]TokenVerifier{}
	}
	return s, nil
}

// Session is what every sign-in ends in.
type Session struct {
	Token   string
	UserID  uuid.UUID
	Created bool // a new account, made with an invitation, an admission code or by open sign-up
}

// InviteProof is the invitation a sign-up presents: its id and auth.
type InviteProof struct {
	ID   string
	Auth []byte
}

// ErrNoAccount answers a sign-in by a method no account uses, when the request is
// not a sign-up: the app then offers to make an account.
var ErrNoAccount = errors.New("no account uses this sign-in; sign up to create one")

// createAccount makes a user (with id, when given) inside the caller's transaction:
// a child of the inviter in the invite tree when g is an invite, a root (no inviter,
// no friendship) when it is an admission code, which it spends, or open (the caller
// has counted it with countOpen, if it counts). It locks the invite
// or code and checks it is still live, so a revocation, the inviter's purge or
// another sign-up with the same code since the first check stops the sign-up
// (ErrNotFound) rather than slipping through. Every account starts with a random
// English display name (names.Random, sealed like any display name); a sign-up that
// gives one sets it over this in the same transaction.
func createAccount(ctx context.Context, q *db.Queries, keys *atrest.Keys, g gate, id *uuid.UUID) (db.User, error) {
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
	case g.open:
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
	name, err := names.Random()
	if err != nil {
		return db.User{}, err
	}
	if err := q.SetDisplayName(ctx, db.SetDisplayNameParams{ID: user.ID, DisplayNameEncrypted: keys.SealDisplayName(user.ID, name)}); err != nil {
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
// user handle is the account id, so a discoverable sign-in finds the account. The
// names label the passkey in the phone's password manager: the username, else the
// display name, else "Duongöndro" (a sign-up always has a display name, given or
// drawn at random when the ceremony begins, so only an unnamed account's added
// passkey falls back to it).
type passkeyUser struct {
	id                uuid.UUID
	name, displayName string
	credentials       []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte { return u.id[:] }
func (u *passkeyUser) WebAuthnName() string {
	return cmp.Or(u.name, u.displayName, "Duongöndro")
}
func (u *passkeyUser) WebAuthnDisplayName() string {
	return cmp.Or(u.displayName, u.name, "Duongöndro")
}
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *SignIn) loadPasskeyUser(ctx context.Context, q *db.Queries, id uuid.UUID) (*passkeyUser, error) {
	rows, err := s.keys.Credentials(q.ListCredentials(ctx, id))
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

func (s *SignIn) saveCeremony(ctx context.Context, data *webauthn.SessionData, userID *uuid.UUID, g gate, profile SignUpProfile) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.UUID{}, err
	}
	if _, err := s.q.PurgeExpiredWebauthnSessions(ctx); err != nil {
		return uuid.UUID{}, err
	}
	id := uuid.NewV7()
	row := atrest.IDRow(id)
	return id, s.q.CreateWebauthnSession(ctx, db.CreateWebauthnSessionParams{ID: id, Data: raw, UserID: userID,
		InviteID: g.inviteID, AdmissionID: g.admissionID, SignUp: g != (gate{}),
		UsernameEncrypted:    s.keys.SealOptional(atrest.WebauthnSessionsUsername, row, profile.Username),
		DisplayNameEncrypted: s.keys.SealOptional(atrest.WebauthnSessionsDisplayName, row, profile.DisplayName),
		GenderEncrypted:      s.keys.SealOptional(atrest.WebauthnSessionsGender, row, profile.Gender)})
}

func (s *SignIn) consumeCeremony(ctx context.Context, id uuid.UUID) (atrest.Ceremony, webauthn.SessionData, error) {
	var data webauthn.SessionData
	row, err := s.keys.Ceremony(s.q.ConsumeWebauthnSession(ctx, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return row, data, invalid("the passkey ceremony expired or is unknown; start again")
	} else if err != nil {
		return row, data, err
	}
	return row, data, json.Unmarshal(row.Data, &data)
}

// SignUpProfile is the profile a passkey sign-up may carry, each field optional, under
// PATCH /api/me's rules; it names the passkey and is set on the new account.
type SignUpProfile struct {
	Username, DisplayName, Gender *string
}

// clean validates the profile and returns it normalized.
func (p SignUpProfile) clean() (SignUpProfile, error) {
	var out SignUpProfile
	if p.Username != nil {
		name, err := cleanUsername(*p.Username)
		if err != nil {
			return out, err
		}
		out.Username = &name
	}
	if p.DisplayName != nil {
		name, err := cleanDisplayName(*p.DisplayName)
		if err != nil {
			return out, err
		}
		if name != "" { // an empty one is none given: the random name stays
			out.DisplayName = &name
		}
	}
	if p.Gender != nil {
		if err := checkGender(*p.Gender); err != nil {
			return out, err
		}
		out.Gender = p.Gender
	}
	return out, nil
}

// BeginPasskeySignUp starts creating an account with a passkey; the invitation or
// admission code is checked now and again when the ceremony finishes, and so is the
// username, if the profile has one. An open sign-up checks the client address's
// limit now and counts against it when it finishes.
func (s *SignIn) BeginPasskeySignUp(ctx context.Context, proof SignUpProof, profile SignUpProfile) (Ceremony, error) {
	profile, err := profile.clean()
	if err != nil {
		return Ceremony{}, err
	}
	g, err := s.checkProof(ctx, proof)
	if err != nil {
		return Ceremony{}, err
	}
	if g.open && !s.openLimit.allowed(clientAddress(ctx)) {
		return Ceremony{}, ErrSignUpRateLimited
	}
	if profile.Username != nil {
		if taken, err := s.q.UsernameTaken(ctx, s.keys.HashOptional(profile.Username)); err != nil {
			return Ceremony{}, err
		} else if taken {
			return Ceremony{}, conflict("that username is taken")
		}
	}
	// Without a display name, the random one is drawn now rather than when the account
	// is made, so that it labels the passkey in the password manager too (not
	// "Duongöndro" on every account's) and the label and the name match.
	if profile.DisplayName == nil {
		name, err := names.Random()
		if err != nil {
			return Ceremony{}, err
		}
		profile.DisplayName = &name
	}
	id := uuid.NewV7()
	u := &passkeyUser{id: id}
	if profile.Username != nil {
		u.name = *profile.Username
	}
	if profile.DisplayName != nil {
		u.displayName = *profile.DisplayName
	}
	options, data, err := s.web.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		return Ceremony{}, err
	}
	sid, err := s.saveCeremony(ctx, data, &id, g, profile)
	return Ceremony{SessionID: sid, Options: options}, err
}

// BeginPasskeyAdd starts adding a passkey to a signed-in account, named after its
// username or display name.
func (s *SignIn) BeginPasskeyAdd(ctx context.Context, userID uuid.UUID) (Ceremony, error) {
	u, err := s.loadPasskeyUser(ctx, s.q, userID)
	if err != nil {
		return Ceremony{}, err
	}
	account, err := s.keys.User(s.q.GetUser(ctx, userID))
	if err != nil {
		return Ceremony{}, err
	}
	if account.Username != nil {
		u.name = *account.Username
	}
	u.displayName = account.DisplayName
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
	sid, err := s.saveCeremony(ctx, data, &userID, gate{}, SignUpProfile{})
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

func (s *SignIn) finishRegistration(ctx context.Context, row atrest.Ceremony, data webauthn.SessionData, credential json.RawMessage, signedIn *uuid.UUID) (Session, error) {
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
	if err := s.countOpen(ctx, g); err != nil {
		return Session{}, err
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if signUp {
			// The invite may have been revoked or expired, or the admission code spent,
			// since the ceremony began.
			if _, err := createAccount(ctx, q, s.keys, g, row.UserID); err != nil {
				return err
			}
			// A blank name from the ceremony is none given: the random name stays.
			name := row.DisplayName
			if name != nil && names.Clean(*name) == "" {
				name = nil
			}
			if row.Username != nil || name != nil || row.Gender != nil {
				p := profileParams(s.keys, *row.UserID, ProfileUpdate{DisplayName: name,
					SetUsername: row.Username != nil, Username: row.Username, SetGender: row.Gender != nil, Gender: row.Gender})
				// The username may have been taken since the ceremony began.
				if err := usernameConflict(q.UpdateProfile(ctx, p)); err != nil {
					return err
				}
			}
		}
		return q.CreateCredential(ctx, db.CreateCredentialParams{ID: cred.ID, UserID: *row.UserID,
			DataEncrypted: s.keys.Seal(atrest.CredentialsData, atrest.RowOf(cred.ID), raw)})
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

// ceremonyGate is the invite or admission code a sign-up ceremony began with, or
// open for one with neither; zero for a sign-in or for adding a passkey.
func ceremonyGate(row atrest.Ceremony) gate {
	return gate{inviteID: row.InviteID, admissionID: row.AdmissionID,
		open: row.SignUp && row.InviteID == nil && row.AdmissionID == nil}
}

// BeginPasskeySignIn starts a discoverable sign-in: the phone offers its passkeys.
func (s *SignIn) BeginPasskeySignIn(ctx context.Context) (Ceremony, error) {
	options, data, err := s.web.BeginDiscoverableLogin()
	if err != nil {
		return Ceremony{}, err
	}
	sid, err := s.saveCeremony(ctx, data, nil, gate{}, SignUpProfile{})
	return Ceremony{SessionID: sid, Options: options}, err
}

func (s *SignIn) FinishPasskeySignIn(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage) (Session, error) {
	row, data, err := s.consumeCeremony(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	return s.finishSignIn(ctx, row, data, credential)
}

func (s *SignIn) finishSignIn(ctx context.Context, row atrest.Ceremony, data webauthn.SessionData, credential json.RawMessage) (Session, error) {
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
	if err := s.q.UpdateCredential(ctx, db.UpdateCredentialParams{ID: cred.ID,
		DataEncrypted: s.keys.Seal(atrest.CredentialsData, atrest.RowOf(cred.ID), raw)}); err != nil {
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
