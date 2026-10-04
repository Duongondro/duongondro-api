package push

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"testing"
)

func TestAPNsPayloadShape(t *testing.T) {
	b, err := APNsPayload(DoneToday("Tomasz", "dorje-sempa", 42, "2026-10-04"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"aps": map[string]any{
			"alert": map[string]any{
				"loc-key":  "DONE_TODAY",
				"loc-args": []any{"Tomasz", "dorje-sempa", "42"},
			},
			"sound":           "default",
			"mutable-content": float64(1),
		},
		"kind":     "done_today",
		"practice": "dorje-sempa",
		"day":      "2026-10-04",
		"current":  "42",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("APNs payload\n got %v\nwant %v", got, want)
	}
	alert := got["aps"].(map[string]any)["alert"].(map[string]any)
	for _, k := range []string{"body", "title"} {
		if _, ok := alert[k]; ok {
			t.Errorf("payload carries literal %s text", k)
		}
	}
}

func TestFCMMessageShape(t *testing.T) {
	b, err := FCMMessage("tok", Poke("Dolma", "0190f3a1-7b2c-7d4e-8f00-123456789abc"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"message": map[string]any{
			"token": "tok",
			"android": map[string]any{
				"notification": map[string]any{
					"body_loc_key":  "POKE",
					"body_loc_args": []any{"Dolma"},
				},
			},
			"data": map[string]any{"kind": "poke", "friend": "0190f3a1-7b2c-7d4e-8f00-123456789abc"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FCM message\n got %v\nwant %v", got, want)
	}
}

func TestLogSender(t *testing.T) {
	s := LogSender{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := s.Send(context.Background(), []Token{{Platform: "apns", Token: "a"}, {Platform: "fcm", Token: "b"}}, Poke("x", "y"))
	if err != nil {
		t.Fatal(err)
	}
}
