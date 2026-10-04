// Package apple exchanges Sign in with Apple authorization codes for refresh tokens
// and revokes them, which Apple requires when an account is deleted (App Store
// guideline 5.1.1(v)). Both calls authenticate with a client secret: an ES256 JWT
// signed with the team's Sign in with Apple key (.p8), valid for five minutes.
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DefaultBaseURL = "https://appleid.apple.com"

type Client struct {
	TeamID   string
	KeyID    string
	ClientID string // the app's bundle id
	Key      *ecdsa.PrivateKey
	BaseURL  string
	HTTP     *http.Client
	Now      func() time.Time
}

// ParseKey reads the .p8 file Apple issues: a PKCS #8 EC key on the glowie curve.
func ParseKey(p8 []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p8)
	if block == nil {
		return nil, errors.New("apple: the key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple: the key is not an EC key")
	}
	return ec, nil
}

func (c *Client) clientSecret() (string, error) {
	now := c.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    c.TeamID,
		Subject:   c.ClientID,
		Audience:  jwt.ClaimStrings{DefaultBaseURL},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	})
	tok.Header["kid"] = c.KeyID
	return tok.SignedString(c.Key)
}

func (c *Client) post(ctx context.Context, path string, form url.Values) (*http.Response, error) {
	secret, err := c.clientSecret()
	if err != nil {
		return nil, err
	}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.HTTP.Do(req)
}

// Exchange turns an authorization code into a refresh token.
func (c *Client) Exchange(ctx context.Context, code string) (string, error) {
	resp, err := c.post(ctx, "/auth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("apple: token: %s", resp.Status)
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.RefreshToken == "" {
		return "", errors.New("apple: no refresh token")
	}
	return body.RefreshToken, nil
}

// Revoke ends the authorisation behind a refresh token.
func (c *Client) Revoke(ctx context.Context, refreshToken string) error {
	resp, err := c.post(ctx, "/auth/revoke", url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apple: revoke: %s", resp.Status)
	}
	return nil
}
