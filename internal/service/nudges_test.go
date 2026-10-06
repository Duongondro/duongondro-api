package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/push"
)

type sent struct {
	token string
	msg   push.Message
}

type fakeSender struct {
	mu   sync.Mutex
	sent []sent
}

func (f *fakeSender) Send(_ context.Context, _, token string, m push.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if token == "gone" {
		return push.ErrUnregistered
	}
	f.sent = append(f.sent, sent{token, m})
	return nil
}

func (f *fakeSender) take() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.sent
	f.sent = nil
	return out
}

// boToken is an APNs device token: hexadecimal.
const boToken = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"

func TestNudges(t *testing.T) {
	f := setup(t)
	social := NewSocial(f.pool)
	sender := &fakeSender{}
	n := NewNudges(f.pool, sender)
	ctx := t.Context()
	ana, bo := f.member(), f.member()
	_ = social.SetDisplayName(ctx, ana.ID, "Ana")
	ana.User = f.reload(ana.User)
	auth := f.invite(social, ana, "N2DGESXY")
	p, sg := acceptance(bo, "N2DGESXY")
	if _, err := social.Redeem(ctx, bo.User, "N2DGESXY", auth, p, sg); err != nil {
		t.Fatal(err)
	}
	boPhone, _ := f.device(bo.User, "hardware")
	anaPhone, _ := f.device(ana.User, "tee")
	if err := n.PutToken(ctx, bo.ID, boPhone.ID, "apns", "not hex"); !isValidation(err) {
		t.Fatalf("a malformed APNs token: %v", err)
	}
	if err := n.PutToken(ctx, bo.ID, boPhone.ID, "apns", boToken); err != nil {
		t.Fatal(err)
	}
	if err := n.PutToken(ctx, ana.ID, boPhone.ID, "apns", boToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a token for someone else's device: %v", err)
	}
	if err := n.PutToken(ctx, ana.ID, anaPhone.ID, "fcm", "gone"); err != nil {
		t.Fatal(err)
	}

	// Done today goes only to friends who opted in.
	n.DoneToday(ctx, ana.User, "dorje-sempa", 42)
	n.drain(ctx)
	if got := sender.take(); len(got) != 0 {
		t.Fatalf("sent without an opt-in: %v", got)
	}
	if err := n.SetNotifyDone(ctx, bo.ID, ana.ID, true); err != nil {
		t.Fatal(err)
	}
	n.DoneToday(ctx, ana.User, "dorje-sempa", 42)
	n.drain(ctx)
	got := sender.take()
	if len(got) != 1 || got[0].token != boToken || got[0].msg.LocKey != LocFriendDone ||
		got[0].msg.LocArgs[0] != "Ana" || got[0].msg.LocArgs[2] != "42" {
		t.Fatalf("done today: %+v", got)
	}

	// One poke per friend per day; strangers cannot be poked.
	if err := n.Poke(ctx, bo.User, ana.ID); err != nil {
		t.Fatal(err)
	}
	if err := n.Poke(ctx, bo.User, ana.ID); !errors.Is(err, ErrAlreadyPoked) {
		t.Fatalf("second poke: %v", err)
	}
	if err := n.Poke(ctx, bo.User, f.member().ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("poking a stranger: %v", err)
	}
	n.drain(ctx) // ana's only token is unregistered: it is dropped
	if tokens, _ := f.q.PushTokensOf(ctx, ana.ID); len(tokens) != 0 {
		t.Fatalf("an unregistered token was kept: %v", tokens)
	}

	// A public streak within two hours of its deadline is nudged once.
	st := e2ee.Streak{Current: 7, Day: today(0), Deadline: time.Now().Add(90 * time.Minute).UnixMilli(), Longest: 7, Practice: "mandala", Seq: 1, User: bo.ID.String()}
	payload, sig := sign(bo, e2ee.TypeStreak, st)
	if _, _, err := social.PutStreak(ctx, bo.User, "mandala", payload, sig); err != nil {
		t.Fatal(err)
	}
	n.SweepAtRisk(ctx)
	n.SweepAtRisk(ctx)
	n.drain(ctx)
	got = sender.take()
	if len(got) != 1 || got[0].msg.LocKey != LocStreakAtRisk || got[0].msg.LocArgs[1] != "7" {
		t.Fatalf("streak at risk: %+v", got)
	}
}
