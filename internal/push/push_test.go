package push

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAPNs(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var got map[string]any
	apple := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")
		if _, err := jwt.Parse(auth, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"})); err != nil ||
			r.Header.Get("apns-topic") != "app.duongondro.ios" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/gone") {
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"reason":"Unregistered"}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer apple.Close()
	a := &APNs{TeamID: "TEAM", KeyID: "KEY", Topic: "app.duongondro.ios", Key: key,
		BaseURL: map[string]string{"apns": apple.URL}, HTTP: apple.Client(), Now: time.Now}

	msg := Message{LocKey: "FRIEND_DONE", LocArgs: []string{"Tomasz", "dorje-sempa", "42"}, ThreadID: "friend"}
	if err := a.Send(t.Context(), "apns", "abc", msg); err != nil {
		t.Fatal(err)
	}
	alert := got["aps"].(map[string]any)["alert"].(map[string]any)
	if alert["loc-key"] != "FRIEND_DONE" || len(alert["loc-args"].([]any)) != 3 {
		t.Fatalf("payload %v", got)
	}
	if err := a.Send(t.Context(), "apns", "gone", msg); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("unregistered token: %v", err)
	}
}

func TestFCM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokens := 0
	var got map[string]any
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			tokens++
			_ = r.ParseForm()
			if _, err := jwt.Parse(r.PostForm.Get("assertion"), func(*jwt.Token) (any, error) { return &key.PublicKey, nil }); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29", "expires_in": 3600})
		case r.Header.Get("Authorization") != "Bearer ya29":
			w.WriteHeader(http.StatusUnauthorized)
		case strings.Contains(r.URL.Path, "/projects/duongondro/messages:send"):
			_ = json.NewDecoder(r.Body).Decode(&got)
			if got["message"].(map[string]any)["token"] == "gone" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`))
			}
		}
	}))
	defer google.Close()
	f := &FCM{ProjectID: "duongondro", ClientEmail: "push@duongondro.iam.gserviceaccount.com", Key: key,
		TokenURL: google.URL + "/token", BaseURL: google.URL, HTTP: google.Client(), Now: time.Now}

	msg := Message{LocKey: "POKE", LocArgs: []string{"Ana"}}
	for i := 0; i < 2; i++ {
		if err := f.Send(t.Context(), "fcm", "abc", msg); err != nil {
			t.Fatal(err)
		}
	}
	if tokens != 1 {
		t.Fatalf("fetched %d access tokens for two sends", tokens)
	}
	n := got["message"].(map[string]any)["android"].(map[string]any)["notification"].(map[string]any)
	if n["body_loc_key"] != "POKE" {
		t.Fatalf("payload %v", got)
	}
	if err := f.Send(t.Context(), "fcm", "gone", msg); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("unregistered token: %v", err)
	}
}
