package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// Open sign-up (design: Social › Open sign-up, decision 20): with OPEN_SIGNUP=true a
// sign-up that marks itself as one (signUp: true) needs no invitation or admission
// code. The account is a root of the invite tree and makes no friendship. Such
// sign-ups by passkey, Apple or Google are limited per client address when they make
// the account; e-mail ones, whose link may go to any address, when they ask for the
// mail, under a limit of their own beside the magic link's per-address one.

// OpenSignUpLimit and OpenSignUpWindow: at most five accounts without an invitation
// an hour from one client address.
// OpenSignUpMailLimit: at most ten magic-link requests an hour marked as an open
// sign-up from one client address, each counted whether or not it is mailed, so
// that mail volume (the relay's quota, the sender's reputation) and catch-all
// domains stay bounded.
const (
	OpenSignUpLimit     = 5
	OpenSignUpMailLimit = 10
	OpenSignUpWindow    = time.Hour
)

// ErrSignUpMailRateLimited answers an open magic-link request beyond the client
// address's limit (429).
var ErrSignUpMailRateLimited = errors.New("too many sign-up mails requested from this network; try again later, or use an invitation")

// ErrInvitationRequired answers a sign-up with neither an invitation nor an admission
// code when the server does not allow open sign-up (403, as ErrNoAccount).
var ErrInvitationRequired = errors.New("an invitation or an admission code is needed to create an account")

// ErrSignUpRateLimited answers an open sign-up beyond the client address's limit (429).
var ErrSignUpRateLimited = errors.New("too many new accounts from this network; try again later, or use an invitation")

type clientAddressKey struct{}

// WithClientAddress puts the client's address, as the server determined it (only
// what Caddy appended to X-Forwarded-For is trusted), where the open sign-up limit
// finds it. The address is never logged or stored.
func WithClientAddress(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, clientAddressKey{}, addr)
}

func clientAddress(ctx context.Context) string {
	addr, _ := ctx.Value(clientAddressKey{}).(string)
	return addr
}

// addressLimiter counts open sign-ups per client address over a sliding window, in
// memory only: a restart forgets it. Addresses are held only as an HMAC under a key
// drawn when the process starts, never in the clear, and never logged or stored.
type addressLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time
	key    []byte

	mu        sync.Mutex
	seen      map[[16]byte][]time.Time
	lastSweep time.Time
}

func newAddressLimiter(limit int, window time.Duration) *addressLimiter {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return &addressLimiter{limit: limit, window: window, now: time.Now, key: key, seen: map[[16]byte][]time.Time{}}
}

func (l *addressLimiter) id(addr string) [16]byte {
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(addr))
	var id [16]byte
	copy(id[:], mac.Sum(nil))
	return id
}

// recent returns the address's sign-ups within the window, dropping older ones, and
// now forgets every address with none left, at most once a window. l.mu is held.
func (l *addressLimiter) recent(id [16]byte, now time.Time) []time.Time {
	if now.Sub(l.lastSweep) >= l.window {
		for k, times := range l.seen {
			if len(times) == 0 || now.Sub(times[len(times)-1]) >= l.window {
				delete(l.seen, k)
			}
		}
		l.lastSweep = now
	}
	times := l.seen[id]
	i := 0
	for i < len(times) && now.Sub(times[i]) >= l.window {
		i++
	}
	times = times[i:]
	if len(times) == 0 {
		delete(l.seen, id)
		return nil
	}
	l.seen[id] = times
	return times
}

// allowed reports whether the address may make another account now, without
// counting one: a passkey ceremony checks it when it begins.
func (l *addressLimiter) allowed(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(l.id(addr), l.now())) < l.limit
}

// take counts an account made from the address, or reports false beyond the limit.
func (l *addressLimiter) take(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	id, now := l.id(addr), l.now()
	times := l.recent(id, now)
	if len(times) >= l.limit {
		return false
	}
	l.seen[id] = append(times, now)
	return true
}

// SetOpenSignUpClock replaces the clock of the open sign-up limit (for tests).
func (s *SignIn) SetOpenSignUpClock(now func() time.Time) {
	s.openLimit.now, s.openMailLimit.now = now, now
}

// admitOpen lets an open sign-up (g.open) make its account: refused when the server
// no longer allows open sign-up, and, when counted, beyond the client address's limit.
// Other gates pass untouched.
func (s *SignIn) admitOpen(ctx context.Context, g gate, counted bool) error {
	if !g.open {
		return nil
	}
	if !s.openSignUp {
		return ErrInvitationRequired
	}
	if counted && !s.openLimit.take(clientAddress(ctx)) {
		return ErrSignUpRateLimited
	}
	return nil
}
