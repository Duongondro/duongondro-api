// Package oidc verifies the ID tokens of Sign in with Apple and Google sign-in: an
// RS256 JWT signed by a key in the provider's published JWKS, from the expected
// issuer, for one of our client ids, unexpired. Keys are cached and refetched when a
// token names an unknown one, at most once a minute.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AppleIssuer  = "https://appleid.apple.com"
	AppleJWKS    = "https://appleid.apple.com/auth/keys"
	GoogleIssuer = "https://accounts.google.com"
	GoogleJWKS   = "https://www.googleapis.com/oauth2/v3/certs"
)

// Claims are the ID-token fields sign-in uses.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
}

// ErrInvalidToken covers every reason a token is refused; the reason is logged by
// nobody, since it would help an attacker more than a user.
var ErrInvalidToken = errors.New("the identity token is not valid")

type Verifier struct {
	issuers   []string
	audiences []string
	jwksURL   string
	client    *http.Client
	now       func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// New returns a verifier. Google tokens carry either issuer form, so issuers is a list.
func New(jwksURL string, issuers, audiences []string) *Verifier {
	return &Verifier{issuers: issuers, audiences: audiences, jwksURL: jwksURL,
		client: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
}

func Apple(clientIDs []string) *Verifier {
	return New(AppleJWKS, []string{AppleIssuer}, clientIDs)
}

func Google(clientIDs []string) *Verifier {
	return New(GoogleJWKS, []string{GoogleIssuer, "accounts.google.com"}, clientIDs)
}

type tokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"` // Apple sends "true", Google true
	Nonce         string `json:"nonce"`
}

func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	var c tokenClaims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
		jwt.WithLeeway(time.Minute),
	)
	_, err := parser.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, kid)
	})
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	if !slices.Contains(v.issuers, c.Issuer) || c.Subject == "" {
		return Claims{}, ErrInvalidToken
	}
	if !slices.ContainsFunc(c.Audience, func(a string) bool { return slices.Contains(v.audiences, a) }) {
		return Claims{}, ErrInvalidToken
	}
	verified := c.EmailVerified == true || c.EmailVerified == "true"
	return Claims{Subject: c.Subject, Email: c.Email, EmailVerified: verified, Nonce: c.Nonce}, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if v.now().Sub(v.fetchedAt) < time.Minute && v.keys != nil {
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	keys, err := v.fetch(ctx)
	v.fetchedAt = v.now()
	if err != nil {
		return nil, err
	}
	v.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key %q", kid)
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: %s", resp.Status)
	}
	var set struct {
		Keys []struct {
			Kid, Kty, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return keys, nil
}
