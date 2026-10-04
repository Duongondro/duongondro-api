package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/db/dbtest"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/push"
	"github.com/Duongondro/duongondro-api/internal/store"
)

// fakeMail records sent links.
type fakeMail struct {
	mu    sync.Mutex
	links map[string]string // address → link
}

func (f *fakeMail) SendMagicLink(_ context.Context, to, link string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links[to] = link
	return nil
}

func (f *fakeMail) last(to string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.links[to]
}

// fakePush records notifications.
type fakePush struct {
	mu   sync.Mutex
	sent []sentPush
}

type sentPush struct {
	Tokens []push.Token
	N      push.Notification
}

func (f *fakePush) Send(_ context.Context, tokens []push.Token, n push.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentPush{tokens, n})
	return nil
}

func (f *fakePush) all() []sentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentPush(nil), f.sent...)
}

type fakeRevoker struct {
	mu      sync.Mutex
	revoked []string
}

func (f *fakeRevoker) Revoke(_ context.Context, subject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, subject)
	return nil
}

type env struct {
	t       *testing.T
	srv     *httptest.Server
	store   *store.Store
	mail    *fakeMail
	push    *fakePush
	revoker *fakeRevoker
	now     time.Time
	mu      sync.Mutex
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := dbtest.New(t)
	e := &env{
		t:       t,
		store:   store.New(pool),
		mail:    &fakeMail{links: map[string]string{}},
		push:    &fakePush{},
		revoker: &fakeRevoker{},
		now:     time.Now(),
	}
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		Store:         e.store,
		Mail:          e.mail,
		Push:          e.push,
		AppleRevoker:  e.revoker,
		MagicLinkBase: "https://duongondro.app/m#",
		Now:           e.clock,
	})
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

// user is a signed-in test account with an identity key.
type user struct {
	ID       string
	Token    string
	Identity ed25519.PrivateKey
	Name     string
}

func (e *env) newUser(name string) *user {
	e.t.Helper()
	seed := make([]byte, 32)
	copy(seed, name)
	id := ed25519.NewKeyFromSeed(seed)
	u := &user{ID: ids.NewV7().String(), Identity: id, Name: name}
	ctx := context.Background()
	if err := e.store.CreateUser(ctx, u.ID, name, id.Public().(ed25519.PublicKey)); err != nil {
		e.t.Fatal(err)
	}
	tok, hash := ids.NewToken()
	if err := e.store.CreateSession(ctx, hash, u.ID); err != nil {
		e.t.Fatal(err)
	}
	u.Token = tok
	return u
}

type resp struct {
	Status int
	Body   []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("decode %s: %v", r.Body, err)
	}
}

func (r resp) errCode(t *testing.T) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	r.json(t, &e)
	return e.Error
}

// call sends body (marshalled unless it is []byte or nil) with token.
func (e *env) call(method, path, token string, body any) resp {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		j, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{Status: res.StatusCode, Body: b}
}

func (e *env) want(r resp, status int, code string) {
	e.t.Helper()
	if r.Status != status {
		e.t.Fatalf("status %d, want %d: %s", r.Status, status, r.Body)
	}
	if code != "" {
		if got := r.errCode(e.t); got != code {
			e.t.Fatalf("error %q, want %q", got, code)
		}
	}
}
