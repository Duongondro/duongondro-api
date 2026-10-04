package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/mail"
	"strings"
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

// Mailer sends the magic-link mail (SES in an EU region in production).
type Mailer interface {
	SendMagicLink(ctx context.Context, to, link string) error
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

// ProviderSignIn signs in with an Apple or Google ID token, or, with an invite and no
// account for that provider subject, creates one. nonce is the raw value the app
// passed to the provider: Google echoes it, Apple its SHA-256 in hex; it binds the
// token to this sign-in so a token taken from elsewhere cannot be replayed.
func (s *SignIn) ProviderSignIn(ctx context.Context, provider, idToken, nonce, authCode string, invite *InviteProof) (Session, error) {
	claims, err := s.verify(ctx, provider, idToken, nonce)
	if err != nil {
		return Session{}, err
	}
	refresh := s.exchangeApple(ctx, provider, authCode)
	identity, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: provider, Subject: claims.Subject})
	if err == nil {
		if refresh != nil || verifiedEmail(claims) != nil {
			if err := s.q.UpdateIdentity(ctx, db.UpdateIdentityParams{Provider: provider, Subject: claims.Subject,
				Email: verifiedEmail(claims), RefreshToken: refresh}); err != nil {
				return Session{}, err
			}
		}
		return s.session(ctx, identity.UserID, false)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, err
	}
	if invite == nil {
		return Session{}, ErrNoAccount
	}
	inv, err := s.social.CheckInvite(ctx, invite.ID, invite.Auth)
	if err != nil {
		return Session{}, err
	}
	var user db.User
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if user, err = createAccount(ctx, q, inv.ID, nil); err != nil {
			return err
		}
		return q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: provider, Subject: claims.Subject, UserID: user.ID,
			Email: verifiedEmail(claims), RefreshToken: refresh})
	})
	if repository.IsUniqueViolation(err, "") {
		// The same token signed up twice at once; the other request made the account.
		return s.ProviderSignIn(ctx, provider, idToken, nonce, "", nil)
	} else if err != nil {
		return Session{}, err
	}
	return s.session(ctx, user.ID, true)
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
	return s.q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: provider, Subject: claims.Subject, UserID: userID,
		Email: verifiedEmail(claims), RefreshToken: s.exchangeApple(ctx, provider, authCode)})
}

func (s *SignIn) verify(ctx context.Context, provider, idToken, nonce string) (oidc.Claims, error) {
	v, ok := s.oidc[provider]
	if !ok {
		return oidc.Claims{}, invalid("sign-in with %q is not configured on this server", provider)
	}
	if nonce == "" || len(nonce) > 256 {
		return oidc.Claims{}, invalid("a nonce is required")
	}
	claims, err := v.Verify(ctx, idToken)
	if err != nil {
		return oidc.Claims{}, invalid("the identity token is not valid")
	}
	hashed := sha256.Sum256([]byte(nonce))
	if claims.Nonce != nonce && claims.Nonce != hex.EncodeToString(hashed[:]) {
		return oidc.Claims{}, invalid("the identity token was issued for another sign-in")
	}
	return claims, nil
}

// exchangeApple keeps Apple's refresh token for revocation, when the server has the
// Sign in with Apple key. Signing in does not depend on it.
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

// RequestMagicLink mails a single-use sign-in link valid for 15 minutes. Without an
// account for the address and without an invite it sends nothing but answers the
// same, so the endpoint does not reveal who has an account. A magic link proves
// control of an inbox, not ownership of the practice data, which still needs an
// enrolled device or the recovery code.
func (s *SignIn) RequestMagicLink(ctx context.Context, email string, invite *InviteProof, linkBase string) error {
	if s.mailer == nil {
		return invalid("magic links are not configured on this server")
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return err
	}
	var inviteID *string
	if invite != nil {
		inv, err := s.social.CheckInvite(ctx, invite.ID, invite.Auth)
		if err != nil {
			return err
		}
		inviteID = &inv.ID
	} else if _, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", Subject: email}); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := s.q.PurgeExpiredMagicLinks(ctx); err != nil {
		return err
	}
	if n, err := s.q.CountRecentMagicLinks(ctx, email); err != nil {
		return err
	} else if n >= magicLinksPerWindow {
		return ErrMailRateLimited
	}
	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(token))
	if err := s.q.CreateMagicLink(ctx, db.CreateMagicLinkParams{TokenHash: sum[:], Email: email, InviteID: inviteID}); err != nil {
		return err
	}
	return s.mailer.SendMagicLink(ctx, email, linkBase+token)
}

// RedeemMagicLink signs in with a link's token, creating the account when the link
// was requested with an invite and the address has none yet.
func (s *SignIn) RedeemMagicLink(ctx context.Context, token string) (Session, error) {
	sum := sha256.Sum256([]byte(token))
	link, err := s.q.ConsumeMagicLink(ctx, sum[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, invalid("this sign-in link has expired or was already used")
	} else if err != nil {
		return Session{}, err
	}
	identity, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", Subject: link.Email})
	if err == nil {
		return s.session(ctx, identity.UserID, false)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, err
	}
	if link.InviteID == nil {
		return Session{}, ErrNoAccount
	}
	var user db.User
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if _, err := q.GetLiveInvite(ctx, *link.InviteID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if user, err = createAccount(ctx, q, *link.InviteID, nil); err != nil {
			return err
		}
		email := link.Email
		return q.CreateIdentity(ctx, db.CreateIdentityParams{Provider: "email", Subject: link.Email, UserID: user.ID, Email: &email})
	})
	if err != nil {
		return Session{}, err
	}
	return s.session(ctx, user.ID, true)
}
