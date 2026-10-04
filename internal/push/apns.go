package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	APNsProduction = "https://api.push.apple.com"
	APNsSandbox    = "https://api.sandbox.push.apple.com"
)

// APNs sends with token-based authentication: an ES256 provider token signed with the
// team's .p8 key, reused for up to 50 minutes (Apple refuses tokens older than an hour
// and throttles fresh ones).
type APNs struct {
	TeamID, KeyID, Topic string // Topic is the app's bundle id
	Key                  *ecdsa.PrivateKey
	// BaseURL per platform: "apns" → production, "apns-sandbox" → development builds.
	BaseURL map[string]string
	HTTP    *http.Client // net/http speaks HTTP/2 to Apple over TLS
	Now     func() time.Time

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

func (a *APNs) providerToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.Now()
	if a.token != "" && now.Sub(a.issuedAt) < 50*time.Minute {
		return a.token, nil
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": a.TeamID, "iat": now.Unix()})
	tok.Header["kid"] = a.KeyID
	signed, err := tok.SignedString(a.Key)
	if err != nil {
		return "", err
	}
	a.token, a.issuedAt = signed, now
	return signed, nil
}

func (a *APNs) Send(ctx context.Context, platform, deviceToken string, m Message) error {
	base, ok := a.BaseURL[platform]
	if !ok {
		return fmt.Errorf("apns: no endpoint for %q", platform)
	}
	auth, err := a.providerToken()
	if err != nil {
		return err
	}
	payload := map[string]any{"aps": map[string]any{
		"alert":           map[string]any{"loc-key": m.LocKey, "loc-args": m.LocArgs},
		"sound":           "default",
		"thread-id":       m.ThreadID,
		"mutable-content": 1, // lets the app's extension apply the discreet setting
	}}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+deviceToken, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "bearer "+auth)
	req.Header.Set("apns-topic", a.Topic)
	req.Header.Set("apns-push-type", "alert")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var reason struct{ Reason string }
	_ = json.NewDecoder(resp.Body).Decode(&reason)
	if resp.StatusCode == http.StatusGone || reason.Reason == "BadDeviceToken" || reason.Reason == "Unregistered" {
		return ErrUnregistered
	}
	return fmt.Errorf("apns: %s %s", resp.Status, reason.Reason)
}
