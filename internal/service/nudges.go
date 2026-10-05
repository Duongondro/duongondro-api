package service

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/push"
)

// Push loc-keys, rendered by the phones (design: Social › Nudges).
const (
	LocFriendDone   = "FRIEND_DONE"    // args: name, practice, day count
	LocPoke         = "POKE"           // args: name
	LocStreakAtRisk = "STREAK_AT_RISK" // args: practice, day count
)

// genderedKey picks the loc-key variant for the sender's grammatical gender, so the
// phone can say "Anna ukończyła" rather than "ukończył(a)": FRIEND_DONE_FEMALE,
// FRIEND_DONE_MALE, or the neutral key for nonbinary and unset (design: Localisation
// › Grammatical gender). Every variant exists in every language's strings.
func genderedKey(key string, gender *string) string {
	if gender != nil && (*gender == "male" || *gender == "female") {
		return key + "_" + strings.ToUpper(*gender)
	}
	return key
}

var platforms = map[string]bool{"apns": true, "apns-sandbox": true, "fcm": true}

var apnsToken = regexp.MustCompile(`^[0-9a-fA-F]{32,200}$`)

// ErrAlreadyPoked answers a second poke to the same friend on one UTC day.
var ErrAlreadyPoked = errors.New("you already poked this friend today")

type delivery struct {
	userID uuid.UUID
	msg    push.Message
}

// Nudges sends pushes in the background: a request never waits for APNs or FCM, and
// a full queue drops a nudge (logged) rather than slowing requests down.
type Nudges struct {
	q      *db.Queries
	sender push.Sender
	queue  chan delivery
	now    func() time.Time
}

func NewNudges(pool *pgxpool.Pool, sender push.Sender) *Nudges {
	return &Nudges{q: db.New(pool), sender: sender, queue: make(chan delivery, 1024), now: time.Now}
}

// Run delivers queued nudges and sends streak-at-risk pushes until ctx ends.
func (n *Nudges) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// Deliver what is queued before the process exits, within a few seconds.
			drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			n.drain(drainCtx)
			cancel()
			return
		case d := <-n.queue:
			n.deliver(ctx, d)
		case <-tick.C:
			n.SweepAtRisk(ctx)
		}
	}
}

func (n *Nudges) enqueue(userID uuid.UUID, m push.Message) bool {
	select {
	case n.queue <- delivery{userID: userID, msg: m}:
		return true
	default:
		slog.Warn("Push queue full; nudge dropped", "user_id", userID.String(), "loc_key", m.LocKey)
		return false
	}
}

// deliver sends to every device of the user that has a token, dropping tokens the
// provider no longer knows.
func (n *Nudges) deliver(ctx context.Context, d delivery) {
	if n.sender == nil {
		return
	}
	tokens, err := n.q.PushTokensOf(ctx, d.userID)
	if err != nil {
		slog.WarnContext(ctx, "Loading push tokens failed", "user_id", d.userID.String(), "error", err.Error())
		return
	}
	for _, t := range tokens {
		sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := n.sender.Send(sendCtx, t.Platform, t.Token, d.msg)
		cancel()
		if errors.Is(err, push.ErrUnregistered) {
			if err := n.q.DropPushToken(ctx, db.DropPushTokenParams{Platform: t.Platform, Token: t.Token}); err != nil {
				slog.WarnContext(ctx, "Dropping a push token failed", "error", err.Error())
			}
		} else if err != nil {
			slog.WarnContext(ctx, "Push failed", "user_id", d.userID.String(), "platform", t.Platform, "error", err.Error())
		}
	}
}

// PutToken stores the push token of one of the user's devices.
func (n *Nudges) PutToken(ctx context.Context, userID, deviceID uuid.UUID, platform, token string) error {
	if !platforms[platform] {
		return invalid("platform must be apns, apns-sandbox or fcm")
	}
	if token == "" || len(token) > 4096 || !validText(token) {
		return invalid("token must be 1 to 4096 characters")
	}
	if platform != "fcm" && !apnsToken.MatchString(token) {
		return invalid("an APNs token is hexadecimal")
	}
	dev, err := n.q.GetDevice(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && dev.UserID != userID) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	// A token reaches one device: a phone signed in to another account before loses it.
	if err := n.q.ReleasePushToken(ctx, db.ReleasePushTokenParams{Platform: platform, Token: token, DeviceID: deviceID}); err != nil {
		return err
	}
	return n.q.PutPushToken(ctx, db.PutPushTokenParams{DeviceID: deviceID, Platform: platform, Token: token})
}

// DropDeviceToken removes a device's push token, as its session signs out.
func (n *Nudges) DropDeviceToken(ctx context.Context, deviceID uuid.UUID) (int64, error) {
	return n.q.DeletePushToken(ctx, deviceID)
}

func (n *Nudges) DeleteToken(ctx context.Context, userID, deviceID uuid.UUID) error {
	dev, err := n.q.GetDevice(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && dev.UserID != userID) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	_, err = n.q.DeletePushToken(ctx, deviceID)
	return err
}

// SetNotifyDone opts the user in or out of "done today" pushes from one friend.
func (n *Nudges) SetNotifyDone(ctx context.Context, userID, friendID uuid.UUID, on bool) error {
	rows, err := n.q.SetNotifyDone(ctx, db.SetNotifyDoneParams{UserID: userID, FriendID: friendID, NotifyDone: on})
	if err == nil && rows == 0 {
		return ErrNotFound
	}
	return err
}

// DoneToday tells the friends who opted in that user practised: "Tomasz just did his
// Dorje Sempa · day 42". Only the public statement's contents go out.
func (n *Nudges) DoneToday(ctx context.Context, user db.User, practice string, current int) {
	recipients, err := n.q.DoneTodayRecipients(ctx, user.ID)
	if err != nil {
		slog.WarnContext(ctx, "Loading done-today recipients failed", "user_id", user.ID.String(), "error", err.Error())
		return
	}
	for _, r := range recipients {
		n.enqueue(r, push.Message{LocKey: genderedKey(LocFriendDone, user.Gender), LocArgs: []string{user.DisplayName, practice, strconv.Itoa(current)},
			ThreadID: user.ID.String()})
	}
}

// Poke nudges a friend by hand, once per friend per UTC day.
func (n *Nudges) Poke(ctx context.Context, user db.User, friendID uuid.UUID) error {
	friends, err := n.q.AreFriends(ctx, db.AreFriendsParams{UserID: user.ID, FriendID: friendID})
	if err != nil {
		return err
	}
	if !friends {
		return ErrNotFound
	}
	now := n.now().UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	rows, err := n.q.RecordNudge(ctx, db.RecordNudgeParams{SenderID: user.ID, RecipientID: friendID, Day: day})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrAlreadyPoked
	}
	n.enqueue(friendID, push.Message{LocKey: genderedKey(LocPoke, user.Gender), LocArgs: []string{user.DisplayName}, ThreadID: user.ID.String()})
	return nil
}

// SweepAtRisk sends the streak-at-risk push for public streaks whose signed deadline
// is under two hours away, once per statement. The deadline is an absolute instant,
// so this needs no idea where the user is; private streaks are reminded locally on
// the phone, and the server learns nothing about them.
func (n *Nudges) SweepAtRisk(ctx context.Context) {
	streaks, err := n.q.StreaksAtRisk(ctx)
	if err != nil {
		slog.WarnContext(ctx, "Loading streaks at risk failed", "error", err.Error())
		return
	}
	for _, st := range streaks {
		current, _ := statementCurrent(st.Payload)
		// Marked only once queued: a full queue leaves it for the next sweep.
		if !n.enqueue(st.UserID, push.Message{LocKey: LocStreakAtRisk, LocArgs: []string{st.Practice, strconv.Itoa(current)},
			ThreadID: "streak-" + st.Practice}) {
			return
		}
		if err := n.q.MarkAtRiskSent(ctx, db.MarkAtRiskSentParams{UserID: st.UserID, Practice: st.Practice, AtRiskSentSeq: st.Seq}); err != nil {
			slog.WarnContext(ctx, "Marking a streak nudged failed", "error", err.Error())
		}
	}
}

// drain delivers everything queued, synchronously: for tests.
func (n *Nudges) drain(ctx context.Context) {
	for {
		select {
		case d := <-n.queue:
			n.deliver(ctx, d)
		default:
			return
		}
	}
}
