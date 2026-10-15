package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/repository"
)

// Adding an e-mail address to an existing account (sign-up's optional E-mail step,
// or later from Settings): the address becomes the account's e-mail sign-in, the
// same identity a magic-link sign-up makes, once a mail to it is confirmed by the
// account that asked. The mail is a magic-link row carrying the account's id: it
// shares the per-address limit, the lock, the code's guess count and the expiry with
// sign-in mails, but never signs anyone in. Linking stays explicit: an address is
// added only from a signed-in session, never because it matches.

// EmailConfirmationLimit and EmailConfirmationWindow: at most five confirmation
// mails asked for by one account an hour, counted in memory per account (a restart
// forgets them), beside the per-address limit, so one account cannot mail many
// addresses. Since accounts are free to make, confirmations also count against the
// client address's open sign-up mail limit (OpenSignUpMailLimit, ten an hour, an
// IPv6 address by its /64), shared with open magic-link sign-ups: together they
// bound the unsolicited mail one network can make the server send.
const (
	EmailConfirmationLimit  = 5
	EmailConfirmationWindow = time.Hour
)

// ErrEmailConfirmationRateLimited answers a sixth confirmation request from one
// account within the hour (429).
var ErrEmailConfirmationRateLimited = errors.New("too many confirmation mails for this account; try again later")

// ErrEmailConfirmationNetworkLimited answers a confirmation request beyond the
// client address's mail limit (429).
var ErrEmailConfirmationNetworkLimited = errors.New("too many mails requested from this network; try again later")

// errWrongConfirmationCode answers a typed confirmation code that is wrong, or whose
// mail expired, was used or was replaced, or that took too many wrong guesses: all
// with the same status and body.
var errWrongConfirmationCode = invalid("this code is wrong or has expired; ask for a new confirmation mail")

var errConfirmationLinkGone = invalid("this confirmation link has expired or was already used")

// errEmailTaken answers a confirmed address that another account signs in with. The
// person just proved they control the inbox, so saying so tells them nothing new.
var errEmailTaken = conflict("another Duongöndro account signs in with this address")

// ConfirmLinkBase is the confirmation link's base, from the sign-in link's: `/e`
// before the fragment, so https://duongondro.app/m#<token> becomes
// https://duongondro.app/m/e#<token>, under the app-link paths (/m/*) already.
func ConfirmLinkBase(magicLinkBase string) string {
	if i := strings.LastIndexByte(magicLinkBase, '#'); i >= 0 {
		return strings.TrimSuffix(magicLinkBase[:i], "/") + "/e" + magicLinkBase[i:]
	}
	return strings.TrimSuffix(magicLinkBase, "/") + "/e/"
}

// RequestEmailConfirmation mails the address a link and code that add it to the
// account. An address the account already has is not mailed. Otherwise the answer
// is the same whether or not another account uses the address, and the mail goes
// out either way, in the background; ConfirmEmail tells the person, who then has
// proved they control it.
func (s *SignIn) RequestEmailConfirmation(ctx context.Context, userID uuid.UUID, email, linkBase string) error {
	if s.mailer == nil {
		return invalid("e-mail is not configured on this server")
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return err
	}
	hash := s.keys.HashString(email)
	if identity, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", SubjectHash: hash}); err == nil && identity.UserID == userID {
		return nil
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !s.confirmLimit.take(userID.String()) {
		return ErrEmailConfirmationRateLimited
	}
	if !s.openMailLimit.take(clientAddress(ctx)) {
		return ErrEmailConfirmationNetworkLimited
	}
	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	code, err := randomCode(MagicLinkCodeLength)
	if err != nil {
		return err
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.LockEmail(ctx, atrest.LockKey(hash)); err != nil {
			return err
		}
		if _, err := q.PurgeExpiredMagicLinks(ctx); err != nil {
			return err
		}
		if n, err := q.CountRecentMagicLinks(ctx, hash); err != nil {
			return err
		} else if n >= magicLinksPerWindow {
			return ErrMailRateLimited
		}
		// A newer mail to the address kills its older codes, as a sign-in mail does,
		// and so does a newer confirmation for the account.
		if err := q.KillMagicLinkCodes(ctx, hash); err != nil {
			return err
		}
		if err := q.KillEmailConfirmationCodes(ctx, userID); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(token))
		return q.CreateMagicLink(ctx, db.CreateMagicLinkParams{TokenHash: sum[:],
			EmailEncrypted: s.keys.SealString(atrest.MagicLinksEmail, atrest.RowOf(sum[:]), email), EmailHash: hash,
			CodeHash: s.linkCodeHash(sum[:], code), UserID: &userID})
	})
	if err != nil {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.mailer.SendEmailConfirmation(ctx, email, linkBase+token, FormatCode(code)); err != nil {
			slog.WarnContext(ctx, "Sending an e-mail confirmation failed", "status", mailFailure(err))
		}
	}()
	return nil
}

// ConfirmEmailCode adds the address with the code from the account's newest
// confirmation mail, typed. A wrong code counts against it, and the fifth kills the
// code (not the link). The code is read as a sign-in code is.
func (s *SignIn) ConfirmEmailCode(ctx context.Context, userID uuid.UUID, code string) error {
	code = NormalizeCode(code)
	if len(code) != MagicLinkCodeLength || strings.Trim(code, crockford) != "" {
		return invalid("a confirmation code is %d characters of Crockford base32", MagicLinkCodeLength)
	}
	found, err := s.confirm(ctx, userID, func(q *db.Queries) (string, bool, error) {
		row, err := s.keys.MagicLink(q.LockLiveEmailConfirmation(ctx, userID))
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		} else if err != nil {
			return "", false, err
		}
		if subtle.ConstantTimeCompare(row.CodeHash, s.linkCodeHash(row.TokenHash, code)) != 1 {
			// Committed, so the count holds however the caller retries.
			return "", false, q.RecordWrongMagicLinkCode(ctx, db.RecordWrongMagicLinkCodeParams{TokenHash: row.TokenHash, MaxWrong: maxWrongCodes})
		}
		return row.Email, true, q.DeleteMagicLink(ctx, row.TokenHash)
	})
	if err == nil && !found {
		return errWrongConfirmationCode
	}
	return err
}

// ConfirmEmailLink adds the address with the confirmation link's token; only the
// account that asked for it can use it.
func (s *SignIn) ConfirmEmailLink(ctx context.Context, userID uuid.UUID, token string) error {
	sum := sha256.Sum256([]byte(token))
	found, err := s.confirm(ctx, userID, func(q *db.Queries) (string, bool, error) {
		link, err := s.keys.MagicLink(q.ConsumeEmailConfirmation(ctx, db.ConsumeEmailConfirmationParams{TokenHash: sum[:], UserID: userID}))
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return link.Email, err == nil, err
	})
	if err == nil && !found {
		return errConfirmationLinkGone
	}
	return err
}

// attachEmail makes a confirmed address the account's e-mail sign-in.
func (s *SignIn) attachEmail(ctx context.Context, userID uuid.UUID, email string) error {
	_, err := s.confirm(ctx, userID, func(*db.Queries) (string, bool, error) { return email, true, nil })
	return err
}

// confirm spends a confirmation (take returns its address, or found false when
// there is none to spend, committing whatever take wrote) and, in the same
// transaction, makes the address the account's e-mail sign-in, sealed and keyed by
// its blind index as a magic-link sign-up stores it, in place of the account's
// previous address, if any. A failure, a 409 included, leaves the confirmation
// unspent.
func (s *SignIn) confirm(ctx context.Context, userID uuid.UUID, take func(*db.Queries) (email string, found bool, err error)) (bool, error) {
	found := false
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		// Serialises with RemoveEmail, whose check of the other ways to sign in
		// would otherwise race this, and with other confirmations of the account.
		if _, err := q.LockUser(ctx, userID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		email, ok, err := take(q)
		if err != nil || !ok {
			return err
		}
		found = true
		hash := s.keys.HashString(email)
		existing, err := q.GetIdentity(ctx, db.GetIdentityParams{Provider: "email", SubjectHash: hash})
		if err == nil {
			if existing.UserID == userID {
				return nil
			}
			return errEmailTaken
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := q.DeleteEmailIdentities(ctx, userID); err != nil {
			return err
		}
		return s.createIdentity(ctx, q, "email", email, userID, &email)
	})
	if repository.IsUniqueViolation(err, "") {
		// Another account took the address at the same moment.
		return found, errEmailTaken
	}
	return found, err
}

// RemoveEmail removes the account's e-mail sign-in, unless it is the only way the
// account signs in.
func (s *SignIn) RemoveEmail(ctx context.Context, userID uuid.UUID) error {
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if _, err := q.LockUser(ctx, userID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		identities, err := q.ListIdentities(ctx, userID)
		if err != nil {
			return err
		}
		hasEmail, others := false, 0
		for _, i := range identities {
			if i.Provider == "email" {
				hasEmail = true
			} else {
				others++
			}
		}
		if !hasEmail {
			return nil
		}
		passkeys, err := q.CountCredentials(ctx, userID)
		if err != nil {
			return err
		}
		if others == 0 && passkeys == 0 {
			return conflict("this address is the only way this account signs in; add a passkey, Apple or Google first")
		}
		_, err = q.DeleteEmailIdentities(ctx, userID)
		return err
	})
}

// Email is the address the account signs in with by magic link, if any.
func (s *SignIn) Email(ctx context.Context, userID uuid.UUID) (*string, error) {
	identities, err := s.keys.Identities(s.q.ListIdentities(ctx, userID))
	if err != nil {
		return nil, err
	}
	for _, i := range identities {
		if i.Provider == "email" {
			return &i.Subject, nil
		}
	}
	return nil, nil
}
