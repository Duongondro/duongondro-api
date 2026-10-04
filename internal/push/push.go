// Package push sends notifications through APNs (iOS) and FCM (Android). The server
// stays language-agnostic: a message is a loc-key with arguments (a friend's name, a
// practice id, a day count), and the phone renders it in its own language (design:
// Localisation). Only public data goes into a push.
package push

import (
	"context"
	"errors"
)

// Message is one notification, before it is shaped for a platform.
type Message struct {
	LocKey  string   // e.g. FRIEND_DONE, POKE, STREAK_AT_RISK
	LocArgs []string // in the order the phone's format string takes them
	// ThreadID groups notifications on the lock screen (one thread per friend).
	ThreadID string
}

// ErrUnregistered means the provider no longer knows the token: drop it.
var ErrUnregistered = errors.New("push: token unregistered")

// Sender delivers to one token on one platform ("apns", "apns-sandbox", "fcm").
type Sender interface {
	Send(ctx context.Context, platform, token string, m Message) error
}

// Senders routes by platform; a platform without a sender is skipped.
type Senders map[string]Sender

func (s Senders) Send(ctx context.Context, platform, token string, m Message) error {
	sender, ok := s[platform]
	if !ok {
		return nil
	}
	return sender.Send(ctx, platform, token, m)
}
