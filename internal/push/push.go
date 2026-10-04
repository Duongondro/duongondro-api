// Package push builds APNs and FCM payloads and defines the delivery
// interface. The server stays language-agnostic: a notification is a
// localisation key plus arguments (a friend's display name, a practice key, a
// day count), and the phone renders the text in its own language. No text in
// any language is ever put in a payload, and no language preference is
// stored.
package push

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
)

// Localisation keys. The apps ship a string for each in every language.
const (
	// DoneToday: loc-args [friend's display name, practice key, current
	// streak]. The practice key is also sent as the custom key "practice",
	// so the notification extension can substitute the practice's name in
	// the phone's language.
	LocDoneToday = "DONE_TODAY"
	// Poke: loc-args [friend's display name].
	LocPoke = "POKE"
)

// Token is a registered device push token.
type Token struct {
	DeviceID string
	Platform string // apns or fcm
	Token    string
}

// Notification is what the server wants a phone to show.
type Notification struct {
	Kind    string // custom key "kind": done_today or poke
	LocKey  string
	LocArgs []string
	Data    map[string]string // extra custom keys, public data only
}

// DoneToday announces that a friend practised, from a signed public streak.
func DoneToday(friendName, practice string, current int, day string) Notification {
	return Notification{
		Kind:    "done_today",
		LocKey:  LocDoneToday,
		LocArgs: []string{friendName, practice, strconv.Itoa(current)},
		Data:    map[string]string{"practice": practice, "day": day, "current": strconv.Itoa(current)},
	}
}

// Poke is a friend's manual nudge.
func Poke(friendName, friendID string) Notification {
	return Notification{
		Kind:    "poke",
		LocKey:  LocPoke,
		LocArgs: []string{friendName},
		Data:    map[string]string{"friend": friendID},
	}
}

// APNsPayload is the JSON body for APNs.
func APNsPayload(n Notification) ([]byte, error) {
	args := n.LocArgs
	if args == nil {
		args = []string{}
	}
	body := map[string]any{
		"aps": map[string]any{
			"alert": map[string]any{
				"loc-key":  n.LocKey,
				"loc-args": args,
			},
			"sound":           "default",
			"mutable-content": 1,
		},
		"kind": n.Kind,
	}
	for k, v := range n.Data {
		if k != "aps" && k != "kind" {
			body[k] = v
		}
	}
	return json.Marshal(body)
}

// FCMMessage is the JSON body for FCM's HTTP v1 messages:send.
func FCMMessage(token string, n Notification) ([]byte, error) {
	args := n.LocArgs
	if args == nil {
		args = []string{}
	}
	data := map[string]string{"kind": n.Kind}
	for k, v := range n.Data {
		if k != "kind" {
			data[k] = v
		}
	}
	return json.Marshal(map[string]any{
		"message": map[string]any{
			"token": token,
			"android": map[string]any{
				"notification": map[string]any{
					"body_loc_key":  n.LocKey,
					"body_loc_args": args,
				},
			},
			"data": data,
		},
	})
}

// Sender delivers a notification to device tokens. Implementations drop
// tokens the service reports as unregistered.
type Sender interface {
	Send(ctx context.Context, tokens []Token, n Notification) error
}

// LogSender builds the payloads and logs only the kind and the number of
// tokens. Real APNs (HTTP/2, .p8 JWT) and FCM delivery is a TODO in
// docs/stack.md.
type LogSender struct{ Log *slog.Logger }

func (l LogSender) Send(ctx context.Context, tokens []Token, n Notification) error {
	for _, t := range tokens {
		var err error
		if t.Platform == "fcm" {
			_, err = FCMMessage(t.Token, n)
		} else {
			_, err = APNsPayload(n)
		}
		if err != nil {
			return err
		}
	}
	l.Log.Info("push built (not delivered: no transport configured)", "kind", n.Kind, "tokens", len(tokens))
	return nil
}
