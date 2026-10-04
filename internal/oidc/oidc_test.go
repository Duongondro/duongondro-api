package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fetches := 0
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()
	v := New(jwks.URL, []string{AppleIssuer}, []string{"app.duongondro.ios"})

	sign := func(k *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, _ := tok.SignedString(k)
		return s
	}
	good := jwt.MapClaims{"iss": AppleIssuer, "aud": "app.duongondro.ios", "sub": "001.abc", "exp": time.Now().Add(time.Hour).Unix(),
		"email": "a@privaterelay.appleid.com", "email_verified": "true", "nonce": "n0nce"}

	c, err := v.Verify(t.Context(), sign(key, "k1", good))
	if err != nil || c.Subject != "001.abc" || !c.EmailVerified || c.Nonce != "n0nce" {
		t.Fatalf("good token: %v %+v", err, c)
	}
	bad := map[string]jwt.MapClaims{}
	for name, change := range map[string]func(jwt.MapClaims){
		"another audience": func(m jwt.MapClaims) { m["aud"] = "com.example" },
		"another issuer":   func(m jwt.MapClaims) { m["iss"] = "https://evil.example" },
		"expired":          func(m jwt.MapClaims) { m["exp"] = time.Now().Add(-time.Hour).Unix() },
		"no subject":       func(m jwt.MapClaims) { delete(m, "sub") },
	} {
		m := jwt.MapClaims{}
		for k, v := range good {
			m[k] = v
		}
		change(m)
		bad[name] = m
	}
	for name, m := range bad {
		if _, err := v.Verify(t.Context(), sign(key, "k1", m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := v.Verify(t.Context(), sign(other, "k1", good)); err == nil {
		t.Error("a token signed by another key was accepted")
	}
	if _, err := v.Verify(t.Context(), sign(key, "k2", good)); err == nil {
		t.Error("an unknown kid was accepted")
	}
	if fetches > 2 {
		t.Errorf("fetched the key set %d times; unknown kids must not refetch more than once a minute", fetches)
	}
}
