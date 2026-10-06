package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/oidc"
	"github.com/Duongondro/duongondro-api/internal/repository"
)

// TokenVerifier checks a provider's ID token (internal/oidc in production).
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (oidc.Claims, error)
}

// Mailer sends the magic-link mail (SMTP through Brevo in production): the link, and
// the code to type instead, grouped as XXXX XXXX.
type Mailer interface {
	SendMagicLink(ctx context.Context, to, link, code string) error
}

// AppleRevoker turns Sign in with Apple's authorization code into a refresh token,
// and revokes it when the account is deleted, as Apple requires.
type AppleRevoker interface {
	Exchange(ctx context.Context, code string) (refreshToken string, err error)
	Revoke(ctx context.Context, refreshToken string) error
}

// ErrMailRateLimited answers a fourth magic link to one address within 15 minutes.
var ErrMailRateLimited = errors.New("too many sign-in links to this address; try again in a few minutes")

const magicLinksPerWindow = 3

// MagicLinkCodeLength is 8 Crockford base32 characters, 40 bits: with five guesses
// per link and three links per address per 15 minutes, out of reach.
const MagicLinkCodeLength = 8

// maxWrongCodes kills a link row on its fifth wrong code.
const maxWrongCodes = 5

// errWrongCode answers a typed code that is wrong, or whose link expired, was used,
// was replaced by a newer one or took too many wrong codes: all alike, so the answer
// never says whether the address has a link at all.
var errWrongCode = invalid("this code is wrong or has expired; ask for a new sign-in mail")

// linkCodeHash binds a typed code to its row: SHA-256 over the token hash and the
// normalized code.
func linkCodeHash(tokenHash []byte, code string) []byte {
	sum := sha256.Sum256(append(append([]byte{}, tokenHash...), code...))
	return sum[:]
}

// NewNonce issues a single-use nonce for an Apple or Google sign-in, valid for ten
// minutes. The app passes it to the provider (Apple takes its SHA-256 in hex), and
// the token is accepted only with it, once: a token taken from elsewhere cannot be
// replayed for a session.
func (s *SignIn) NewNonce(ctx context.Context) (string, error) {
	nonce, err := auth.RandomToken()
	if err != nil {
		return "", err
	}
	if err := s.q.PurgeExpiredNonces(ctx); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(nonce))
	return nonce, s.q.CreateNonce(ctx, sum[:])
}

// ProviderSignIn signs in with an Apple or Google ID token, or, with an invite or
// admission code and no account for that provider subject, creates one.
func (s *SignIn) ProviderSignIn(ctx context.Context, provider, idToken, nonce, authCode string, proof *SignUpProof) (Session, error) {
	claims, err := s.verify(ctx, provider, idToken, nonce)
	if err != nil {
		return Session{}, err
	}
	identity, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: provider, Subject: claims.Subject})
	if err == nil {
		s.updateIdentity(ctx, provider, claims, authCode)
		return s.session(ctx, identity.UserID, false)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, err
	}
	if proof == nil {
		return Session{}, ErrNoAccount
	}
	g, err := s.checkProof(ctx, *proof)
	if err != nil {
		return Session{}, err
	}
	var user db.User
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if user, err = createAccount(ctx, q, g, nil); err != nil {
			return err
		}
		return q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: provider, Subject: claims.Subject, UserID: user.ID,
			Email: verifiedEmail(claims)})
	})
	if repository.IsUniqueViolation(err, "") || (errors.Is(err, ErrNotFound) && g.admissionID != nil) {
		// The same account signed up twice at once; the other request made it (and,
		// with an admission code, spent it).
		identity, lookupErr := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: provider, Subject: claims.Subject})
		if errors.Is(lookupErr, pgx.ErrNoRows) && errors.Is(err, ErrNotFound) {
			return Session{}, err
		} else if lookupErr != nil {
			return Session{}, lookupErr
		}
		return s.session(ctx, identity.UserID, false)
	} else if err != nil {
		return Session{}, err
	}
	// Only now that an account exists is Apple's refresh token worth keeping.
	s.updateIdentity(ctx, provider, claims, authCode)
	return s.session(ctx, user.ID, true)
}

// updateIdentity refreshes the stored e-mail and, for Apple, exchanges the code for
// the refresh token kept for revocation. Signing in does not depend on either.
func (s *SignIn) updateIdentity(ctx context.Context, provider string, claims oidc.Claims, authCode string) {
	refresh := s.exchangeApple(ctx, provider, authCode)
	if refresh == nil && verifiedEmail(claims) == nil {
		return
	}
	err := s.q.UpdateIdentity(ctx, db.UpdateIdentityParams{Provider: provider, Subject: claims.Subject,
		Email: verifiedEmail(claims), RefreshToken: refresh})
	if err != nil {
		slog.WarnContext(ctx, "Updating a sign-in identity failed", "provider", provider, "error", err.Error())
		if refresh != nil {
			_ = s.apple.Revoke(ctx, *refresh)
		}
	}
}

// LinkProvider adds an Apple or Google account to a signed-in user. Linking is only
// ever explicit, like this: never by a matching e-mail address.
func (s *SignIn) LinkProvider(ctx context.Context, userID uuid.UUID, provider, idToken, nonce, authCode string) error {
	claims, err := s.verify(ctx, provider, idToken, nonce)
	if err != nil {
		return err
	}
	identity, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: provider, Subject: claims.Subject})
	if err == nil {
		if identity.UserID != userID {
			return conflict("this %s account already signs in to another Duongöndro account", provider)
		}
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	err = s.q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: provider, Subject: claims.Subject, UserID: userID,
		Email: verifiedEmail(claims)})
	if repository.IsUniqueViolation(err, "") {
		return conflict("this %s account was just linked; try again", provider)
	} else if err != nil {
		return err
	}
	s.updateIdentity(ctx, provider, claims, authCode)
	return nil
}

// verify checks the ID token and consumes the server-issued nonce it was bound to:
// Google echoes the nonce, Apple its SHA-256 in hex.
func (s *SignIn) verify(ctx context.Context, provider, idToken, nonce string) (oidc.Claims, error) {
	v, ok := s.oidc[provider]
	if !ok {
		return oidc.Claims{}, invalid("sign-in with %q is not configured on this server", provider)
	}
	if nonce == "" || len(nonce) > 256 {
		return oidc.Claims{}, invalid("a nonce from POST /api/auth/nonces is required")
	}
	claims, err := v.Verify(ctx, idToken)
	if err != nil {
		return oidc.Claims{}, invalid("the identity token is not valid")
	}
	sum := sha256.Sum256([]byte(nonce))
	want := nonce
	if provider == "apple" {
		want = hex.EncodeToString(sum[:])
	}
	if claims.Nonce != want {
		return oidc.Claims{}, invalid("the identity token was issued for another sign-in")
	}
	n, err := s.q.ConsumeNonce(ctx, sum[:])
	if err != nil {
		return oidc.Claims{}, err
	}
	if n == 0 {
		return oidc.Claims{}, invalid("the nonce expired or was already used; start again")
	}
	return claims, nil
}

// exchangeApple trades Sign in with Apple's code for the refresh token kept to revoke
// the authorisation later, when the server has the Sign in with Apple key.
func (s *SignIn) exchangeApple(ctx context.Context, provider, code string) *string {
	if provider != "apple" || code == "" || s.apple == nil {
		return nil
	}
	refresh, err := s.apple.Exchange(ctx, code)
	if err != nil {
		slog.WarnContext(ctx, "Apple code exchange failed", "error", err.Error())
		return nil
	}
	return &refresh
}

// RevokeApple revokes every Sign in with Apple authorisation of the user, before the
// account is purged. A failure is logged and does not stop the purge.
func (s *SignIn) RevokeApple(ctx context.Context, userID uuid.UUID) {
	if s.apple == nil {
		return
	}
	identities, err := s.q.ListIdentities(ctx, userID)
	if err != nil {
		slog.WarnContext(ctx, "Listing identities to revoke failed", "user_id", userID.String(), "error", err.Error())
		return
	}
	for _, id := range identities {
		if id.Provider == "apple" && id.RefreshToken != nil {
			if err := s.apple.Revoke(ctx, *id.RefreshToken); err != nil {
				slog.WarnContext(ctx, "Revoking Sign in with Apple failed", "user_id", userID.String(), "error", err.Error())
			}
		}
	}
}

func verifiedEmail(c oidc.Claims) *string {
	if c.Email == "" || !c.EmailVerified {
		return nil
	}
	e := strings.ToLower(c.Email)
	return &e
}

// --- Magic links ---------------------------------------------------------------

func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > 320 || !auth.ValidText(email) {
		return "", invalid("not an e-mail address")
	}
	return strings.ToLower(email), nil
}

// RequestMagicLink mails a single-use sign-in link valid for 15 minutes, with a code
// that does the same when typed into the app; a newer link to the address makes the
// older ones unusable. Every
// address is treated alike, so the answer and its timing never reveal who has an
// account: the per-address limit applies to all of them, a link is recorded either
// way, and the mail goes out in the background, but only to an address with an
// account or with an invite or admission code, which is checked now and spent only
// when the link makes the account. A magic link proves control of an inbox, not
// ownership of the practice data, which still needs an enrolled device or the
// recovery code.
func (s *SignIn) RequestMagicLink(ctx context.Context, email string, proof *SignUpProof, linkBase string) error {
	if s.mailer == nil {
		return invalid("magic links are not configured on this server")
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return err
	}
	var g gate
	if proof != nil {
		if g, err = s.checkProof(ctx, *proof); err != nil {
			return err
		}
	}
	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	code, err := randomCode(MagicLinkCodeLength)
	if err != nil {
		return err
	}
	send := false
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.LockEmail(ctx, email); err != nil {
			return err
		}
		if _, err := q.PurgeExpiredMagicLinks(ctx); err != nil {
			return err
		}
		if n, err := q.CountRecentMagicLinks(ctx, email); err != nil {
			return err
		} else if n >= magicLinksPerWindow {
			return ErrMailRateLimited
		}
		_, err := q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", Subject: email})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		send = err == nil || g != (gate{})
		if err := q.KillMagicLinks(ctx, email); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(token))
		return q.CreateMagicLink(ctx, db.CreateMagicLinkParams{TokenHash: sum[:], Email: email, InviteID: g.inviteID,
			AdmissionID: g.admissionID, CodeHash: linkCodeHash(sum[:], code)})
	})
	if err != nil || !send {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.mailer.SendMagicLink(ctx, email, linkBase+token, FormatCode(code)); err != nil {
			slog.WarnContext(ctx, "Sending a magic link failed", "error", err.Error())
		}
	}()
	return nil
}

// RedeemMagicLink signs in with a link's token, creating the account when the link
// was requested with an invite or admission code and the address has none yet.
func (s *SignIn) RedeemMagicLink(ctx context.Context, token string) (Session, error) {
	sum := sha256.Sum256([]byte(token))
	link, err := s.q.ConsumeMagicLink(ctx, sum[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, invalid("this sign-in link has expired or was already used")
	} else if err != nil {
		return Session{}, err
	}
	return s.signInWithLink(ctx, link)
}

// RedeemMagicLinkCode signs in with the code from a link's mail, typed with the
// address it went to, as RedeemMagicLink does with the link. Only the newest live link
// to the address counts; a wrong code counts against it, and the fifth kills it. The
// code is read like an admission code (any case, spaces and hyphens ignored, O as 0,
// I and L as 1).
func (s *SignIn) RedeemMagicLinkCode(ctx context.Context, email, code string) (Session, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return Session{}, err
	}
	code = NormalizeCode(code)
	if len(code) != MagicLinkCodeLength || strings.Trim(code, crockford) != "" {
		return Session{}, invalid("a sign-in code is %d characters of Crockford base32", MagicLinkCodeLength)
	}
	var link db.MagicLink
	matched := false
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		row, err := q.LockLiveMagicLinkForEmail(ctx, email)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(row.CodeHash, linkCodeHash(row.TokenHash, code)) != 1 {
			// Committed, so the count holds however the caller retries.
			return q.RecordWrongMagicLinkCode(ctx, db.RecordWrongMagicLinkCodeParams{TokenHash: row.TokenHash, MaxWrong: maxWrongCodes})
		}
		matched, link = true, row
		return q.DeleteMagicLink(ctx, row.TokenHash)
	})
	if err != nil {
		return Session{}, err
	}
	if !matched {
		return Session{}, errWrongCode
	}
	return s.signInWithLink(ctx, link)
}

// signInWithLink signs in the account of a consumed link's address, or creates it
// when the link was requested with an invite or admission code.
func (s *SignIn) signInWithLink(ctx context.Context, link db.MagicLink) (Session, error) {
	identity, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", Subject: link.Email})
	if err == nil {
		return s.session(ctx, identity.UserID, false)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, err
	}
	g := gate{inviteID: link.InviteID, admissionID: link.AdmissionID}
	if g == (gate{}) {
		return Session{}, ErrNoAccount
	}
	var user db.User
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if user, err = createAccount(ctx, q, g, nil); err != nil {
			return err
		}
		email := link.Email
		return q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: "email", Subject: link.Email, UserID: user.ID, Email: &email})
	})
	if repository.IsUniqueViolation(err, "") || (errors.Is(err, ErrNotFound) && g.admissionID != nil) {
		// Two links for one address redeemed at once: the other made the account (and,
		// with an admission code, spent it).
		identity, lookupErr := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", Subject: link.Email})
		if errors.Is(lookupErr, pgx.ErrNoRows) && errors.Is(err, ErrNotFound) {
			return Session{}, err
		} else if lookupErr != nil {
			return Session{}, lookupErr
		}
		return s.session(ctx, identity.UserID, false)
	} else if err != nil {
		return Session{}, err
	}
	return s.session(ctx, user.ID, true)
}
