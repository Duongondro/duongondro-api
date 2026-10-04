package push

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	FCMBaseURL     = "https://fcm.googleapis.com"
	fcmScope       = "https://www.googleapis.com/auth/firebase.messaging"
)

// FCM sends through the HTTP v1 API, authenticated as a service account: a signed
// JWT exchanged for an access token, cached until shortly before it expires.
type FCM struct {
	ProjectID   string
	ClientEmail string
	Key         *rsa.PrivateKey
	TokenURL    string
	BaseURL     string
	HTTP        *http.Client
	Now         func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

func (f *FCM) accessToken(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.Now()
	if f.access != "" && now.Before(f.expires.Add(-time.Minute)) {
		return f.access, nil
	}
	assertion, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.ClientEmail, "scope": fcmScope, "aud": f.TokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}).SignedString(f.Key)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fcm: token: %s", resp.Status)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	f.access, f.expires = body.AccessToken, now.Add(time.Duration(body.ExpiresIn)*time.Second)
	return f.access, nil
}

func (f *FCM) Send(ctx context.Context, _ string, deviceToken string, m Message) error {
	access, err := f.accessToken(ctx)
	if err != nil {
		return err
	}
	msg := map[string]any{"message": map[string]any{
		"token": deviceToken,
		"android": map[string]any{"notification": map[string]any{
			"body_loc_key": m.LocKey, "body_loc_args": m.LocArgs, "tag": m.ThreadID,
		}},
	}}
	body, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.BaseURL+"/v1/projects/"+f.ProjectID+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return requestError("fcm", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	for _, d := range e.Error.Details {
		if d.ErrorCode == "UNREGISTERED" {
			return ErrUnregistered
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrUnregistered
	}
	return fmt.Errorf("fcm: %s %s", resp.Status, e.Error.Status)
}
