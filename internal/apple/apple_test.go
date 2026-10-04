package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestExchangeAndRevoke(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	parsed, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	var revoked string
	apple := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// The client secret must be an ES256 JWT by the team, for the app, signed by the key.
		claims := jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(r.PostForm.Get("client_secret"), &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
			jwt.WithValidMethods([]string{"ES256"}))
		if err != nil || claims.Issuer != "TEAM123" || claims.Subject != "app.duongondro.ios" || r.PostForm.Get("client_id") != "app.duongondro.ios" {
			http.Error(w, "bad client", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": "r-" + r.PostForm.Get("code")})
		case "/auth/revoke":
			revoked = r.PostForm.Get("token")
		}
	}))
	defer apple.Close()
	c := &Client{TeamID: "TEAM123", KeyID: "KEY123", ClientID: "app.duongondro.ios", Key: parsed,
		BaseURL: apple.URL, HTTP: apple.Client(), Now: time.Now}

	refresh, err := c.Exchange(t.Context(), "abc")
	if err != nil || refresh != "r-abc" {
		t.Fatalf("exchange: %v %q", err, refresh)
	}
	if err := c.Revoke(t.Context(), refresh); err != nil || revoked != "r-abc" {
		t.Fatalf("revoke: %v %q", err, revoked)
	}
}
