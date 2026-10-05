package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/repository"
	"github.com/Duongondro/duongondro-api/internal/streak"
)

// Invites last seven days by default (design: Social); the inviter may choose up to
// thirty.
const MaxInviteLifetime = 30 * 24 * time.Hour

// Invite ids are 8 Crockford base32 characters (40 bits), uppercase as in the QR code.
var inviteIDPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{8}$`)

var practicePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type Social struct {
	pool *pgxpool.Pool
	q    *db.Queries
	now  func() time.Time
}

func NewSocial(pool *pgxpool.Pool) *Social {
	return &Social{pool: pool, q: db.New(pool), now: time.Now}
}

// NormalizeInviteID upper-cases an id, as links may arrive in either case.
func NormalizeInviteID(id string) string { return strings.ToUpper(id) }

// decodeStatement verifies a signed statement by key and decodes its payload into v,
// which must be the canonical form: verifiers check the bytes they receive, so the
// server stores only bytes every client would produce for the same content.
func decodeStatement(key []byte, typ string, payload, signature []byte, v any) error {
	if key == nil {
		return conflict("set the identity key first")
	}
	if !e2ee.VerifyStatement(key, typ, payload, signature) {
		return invalid("the signature does not verify against the identity key")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("payload is not a %s statement: %v", typ, err)
	}
	if canonical, err := e2ee.Marshal(v); err != nil || !bytes.Equal(canonical, payload) {
		return invalid("payload is not in canonical form (compact JSON, keys in order)")
	}
	return nil
}

func hashAuth(auth []byte) []byte {
	sum := sha256.Sum256(auth)
	return sum[:]
}

// CreateInvite stores a reusable invitation. The payload is the inviter's signed
// invite statement naming this id, the inviter and their identity key, and the
// expiry; the server stores only a hash of auth.
func (s *Social) CreateInvite(ctx context.Context, user db.User, id string, auth []byte, expiresAt time.Time, payload, signature, mac []byte) error {
	id = NormalizeInviteID(id)
	if !inviteIDPattern.MatchString(id) {
		return invalid("the invite id must be 8 Crockford base32 characters")
	}
	if len(auth) != 32 || len(mac) != 32 {
		return invalid("auth and mac are 32 bytes each")
	}
	now := s.now()
	if !expiresAt.After(now) || expiresAt.After(now.Add(MaxInviteLifetime)) {
		return invalid("expiresAt must be in the future and at most 30 days ahead")
	}
	var st e2ee.Invite
	if err := decodeStatement(user.IdentityPublicKey, e2ee.TypeInvite, payload, signature, &st); err != nil {
		return err
	}
	if st.InviteID != id || st.Inviter != user.ID.String() || !bytes.Equal(st.InviterIdentityPk, user.IdentityPublicKey) ||
		st.ExpiresAt != expiresAt.UnixMilli() {
		return invalid("the invite statement does not match this invite, inviter, key and expiry")
	}
	err := s.q.CreateInvite(ctx, db.CreateInviteParams{
		ID: id, InviterID: user.ID, AuthHash: hashAuth(auth), Payload: payload, Signature: signature, Mac: mac,
		ExpiresAt: time.UnixMilli(st.ExpiresAt),
	})
	if repository.IsUniqueViolation(err, "") {
		return conflict("that invite id is taken; draw another")
	}
	return err
}

// Invite returns a live invite for the invitee's app to check before redeeming. It
// needs no session: the invitee has none yet, and the id alone (40 bits, from a link
// or QR code shared on purpose) is what the invite tree already gives away.
func (s *Social) Invite(ctx context.Context, id string) (db.Invite, error) {
	inv, err := s.q.GetLiveInvite(ctx, NormalizeInviteID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return inv, ErrNotFound
	}
	return inv, err
}

func (s *Social) Invites(ctx context.Context, userID uuid.UUID) ([]db.Invite, error) {
	return s.q.ListInvites(ctx, userID)
}

func (s *Social) RevokeInvite(ctx context.Context, userID uuid.UUID, id string) error {
	n, err := s.q.RevokeInvite(ctx, db.RevokeInviteParams{ID: NormalizeInviteID(id), InviterID: userID})
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

// Redeem makes the user and the inviter friends. auth proves the user holds the
// link's secret; the acceptance, signed by the user's identity key, names this
// invite, the user and their key, so the inviter's phone can pin it. A wrong auth,
// a revoked or expired invite and an unknown id all answer the same 404.
func (s *Social) Redeem(ctx context.Context, user db.User, id string, auth, payload, signature []byte) (inviter uuid.UUID, err error) {
	id = NormalizeInviteID(id)
	var st e2ee.Acceptance
	if err := decodeStatement(user.IdentityPublicKey, e2ee.TypeAcceptance, payload, signature, &st); err != nil {
		return uuid.UUID{}, err
	}
	if st.InviteID != id || st.Invitee != user.ID.String() || !bytes.Equal(st.InviteeIdentityPk, user.IdentityPublicKey) {
		return uuid.UUID{}, invalid("the acceptance does not name this invite, user and key")
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		inv, err := q.LockInvite(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if inv.RevokedAt != nil || !inv.ExpiresAt.After(s.now()) || subtle.ConstantTimeCompare(inv.AuthHash, hashAuth(auth)) != 1 {
			return ErrNotFound
		}
		if inv.InviterID == user.ID {
			return invalid("an invite cannot be redeemed by its own inviter")
		}
		blocked, err := q.IsBlockedEitherWay(ctx, db.IsBlockedEitherWayParams{BlockerID: user.ID, BlockedID: inv.InviterID})
		if err != nil {
			return err
		}
		if blocked {
			// The same answer as any unusable invite, so nobody learns of a block.
			return ErrNotFound
		}
		if err := q.RecordRedemption(ctx, db.RecordRedemptionParams{InviteID: id, InviteeID: user.ID, Payload: payload, Signature: signature}); err != nil {
			return err
		}
		inviter = inv.InviterID
		return q.Befriend(ctx, db.BefriendParams{UserID: user.ID, FriendID: inv.InviterID})
	})
	return inviter, err
}

// CheckInvite is the sign-up gate: an account is created only with a live invite
// and its auth. Every sign-in method can sign in; none can sign up without this.
func (s *Social) CheckInvite(ctx context.Context, id string, auth []byte) (db.Invite, error) {
	inv, err := s.Invite(ctx, id)
	if err != nil {
		return inv, err
	}
	if subtle.ConstantTimeCompare(inv.AuthHash, hashAuth(auth)) != 1 {
		return db.Invite{}, ErrNotFound
	}
	return inv, nil
}

func (s *Social) SetDisplayName(ctx context.Context, userID uuid.UUID, name string) error {
	name = strings.TrimSpace(name)
	if !validText(name) || len([]rune(name)) > 64 {
		return invalid("displayName must be valid text of at most 64 characters")
	}
	return s.q.SetDisplayName(ctx, db.SetDisplayNameParams{ID: userID, DisplayName: name})
}

// Genders a person may give; nil clears it (design: Localisation › Grammatical gender).
var genders = map[string]bool{"male": true, "female": true, "nonbinary": true}

func (s *Social) SetGender(ctx context.Context, userID uuid.UUID, gender *string) error {
	if gender != nil && !genders[*gender] {
		return invalid("gender must be male, female or nonbinary")
	}
	return s.q.SetGender(ctx, db.SetGenderParams{ID: userID, Gender: gender})
}

func (s *Social) Friends(ctx context.Context, userID uuid.UUID) ([]db.ListFriendsRow, error) {
	return s.q.ListFriends(ctx, userID)
}

func (s *Social) Unfriend(ctx context.Context, userID, friendID uuid.UUID) error {
	n, err := s.q.Unfriend(ctx, db.UnfriendParams{UserID: userID, FriendID: friendID})
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

// Block ends any friendship and keeps it from coming back through an invite, in both
// directions; with the friendship go the streaks each could see of the other.
func (s *Social) Block(ctx context.Context, userID, otherID uuid.UUID) error {
	if userID == otherID {
		return invalid("you cannot block yourself")
	}
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if _, err := q.GetUser(ctx, otherID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := q.Unfriend(ctx, db.UnfriendParams{UserID: userID, FriendID: otherID}); err != nil {
			return err
		}
		return q.Block(ctx, db.BlockParams{BlockerID: userID, BlockedID: otherID})
	})
}

func (s *Social) Unblock(ctx context.Context, userID, otherID uuid.UUID) error {
	n, err := s.q.Unblock(ctx, db.UnblockParams{BlockerID: userID, BlockedID: otherID})
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Social) Blocks(ctx context.Context, userID uuid.UUID) ([]db.Block, error) {
	return s.q.ListBlocks(ctx, userID)
}

// Report files a report about a friend, or someone the user has blocked: names are
// visible only to friends, so those are the people a user can have seen.
func (s *Social) Report(ctx context.Context, userID, otherID uuid.UUID, reason string) (uuid.UUID, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || !validText(reason) || len([]rune(reason)) > 1000 {
		return uuid.UUID{}, invalid("reason must be valid text of 1 to 1000 characters")
	}
	friends, err := s.q.AreFriends(ctx, db.AreFriendsParams{UserID: userID, FriendID: otherID})
	if err != nil {
		return uuid.UUID{}, err
	}
	if !friends {
		blocks, err := s.q.ListBlocks(ctx, userID)
		if err != nil {
			return uuid.UUID{}, err
		}
		known := false
		for _, b := range blocks {
			known = known || b.BlockedID == otherID
		}
		if !known {
			return uuid.UUID{}, ErrNotFound
		}
	}
	return s.q.CreateReport(ctx, db.CreateReportParams{ReporterID: userID, ReportedID: &otherID, Reason: reason})
}

// PutStreak stores a signed public streak statement for one practice. current and
// longest count tracked days only (imported seeds never reach the server in the
// clear), the seq must go up, and the deadline lets the server time streak-at-risk
// pushes without knowing where the user is.
//
// newDay reports a statement for a later practice day than the stored one (or the
// first): the moment friends who opted in hear "done today".
func (s *Social) PutStreak(ctx context.Context, user db.User, practice string, payload, signature []byte) (st e2ee.Streak, newDay bool, err error) {
	if !practicePattern.MatchString(practice) {
		return st, false, invalid("practice must be a lowercase id of letters, digits and hyphens")
	}
	if err := decodeStatement(user.IdentityPublicKey, e2ee.TypeStreak, payload, signature, &st); err != nil {
		return st, false, err
	}
	if st.User != user.ID.String() || st.Practice != practice {
		return st, false, invalid("the statement names another user or practice")
	}
	if st.Seq < 1 || st.Current < 0 || st.Longest < st.Current {
		return st, false, invalid("seq must be positive and 0 <= current <= longest")
	}
	day, err := streak.ParseDate(st.Day)
	if err != nil {
		return st, false, invalid("day must be YYYY-MM-DD")
	}
	// The deadline is midnight after the next day in some time zone (docs/streaks.md):
	// between the day's start, west of every zone, and three days on. Anything else
	// is not a streak, and would only confuse the at-risk sweep.
	dayStart := time.Date(day.Year, time.Month(day.Month), day.Day, 0, 0, 0, 0, time.UTC)
	deadline := time.UnixMilli(st.Deadline)
	if deadline.Before(dayStart) || deadline.After(dayStart.Add(72*time.Hour)) {
		return st, false, invalid("deadline must fall within three days of day")
	}
	newDay = st.Current > 0
	if old, err := s.q.GetStreak(ctx, db.GetStreakParams{UserID: user.ID, Practice: practice}); err == nil {
		var prev e2ee.Streak
		newDay = newDay && json.Unmarshal(old.Payload, &prev) == nil && prev.Day < st.Day
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return st, false, err
	}
	n, err := s.q.PutStreak(ctx, db.PutStreakParams{
		UserID: user.ID, Practice: practice, Seq: st.Seq, Payload: payload, Signature: signature,
		DeadlineAt: time.UnixMilli(st.Deadline),
	})
	if err == nil && n == 0 {
		return st, false, conflict("seq %d is not above the stored statement's", st.Seq)
	}
	return st, newDay && err == nil, err
}

// statementCurrent reads current from a stored streak payload.
func statementCurrent(payload []byte) (int, error) {
	var st e2ee.Streak
	err := json.Unmarshal(payload, &st)
	return st.Current, err
}

// DeleteStreak makes a practice's streak private again.
func (s *Social) DeleteStreak(ctx context.Context, userID uuid.UUID, practice string) error {
	n, err := s.q.DeleteStreak(ctx, db.DeleteStreakParams{UserID: userID, Practice: practice})
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

// FriendsStreaks returns the newest statement of every public practice of every
// friend. Only friends: who practises at all is itself sensitive.
func (s *Social) FriendsStreaks(ctx context.Context, userID uuid.UUID) ([]db.Streak, error) {
	return s.q.FriendsStreaks(ctx, userID)
}

func (s *Social) OwnStreaks(ctx context.Context, userID uuid.UUID) ([]db.Streak, error) {
	return s.q.OwnStreaks(ctx, userID)
}

// validText reports whether Postgres can store s as text: valid UTF-8 without NUL.
func validText(s string) bool {
	return strings.ToValidUTF8(s, "�") == s && !strings.ContainsRune(s, 0)
}
