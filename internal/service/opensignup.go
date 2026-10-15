package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Open sign-up (design: Social › Open sign-up, decision 20): a sign-up that marks
// itself as one (signUp: true) needs no invitation or admission code; the owner
// decided against a switch for it. The account is a root of the invite tree and makes no friendship. Such
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
var ErrSignUpMailRateLimited = errors.New("too many sign-up mails requested from this network; try again later, or use a friendship code")

// ErrSignUpRateLimited answers an open sign-up beyond the client address's limit (429).
var ErrSignUpRateLimited = errors.New("too many new accounts from this network; try again later, or use a friendship code")

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

// limitKey is what an address is counted under: an IPv4 address whole, an IPv6
// address by its /64, the block one subscriber usually holds whole, so that walking
// through it gains nothing. Anything unparsable counts as itself.
func limitKey(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip.WithZone(""), 64).Masked().String()
}

func (l *addressLimiter) id(addr string) [16]byte {
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(limitKey(addr)))
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

// countOpen counts an account an open sign-up (g.open) by passkey, Apple or Google is
// about to make against the client address's limit, refusing it beyond. Other gates,
// and e-mail sign-ups (limited when they ask for the mail), are not counted.
func (s *SignIn) countOpen(ctx context.Context, g gate) error {
	if g.open && !s.openLimit.take(clientAddress(ctx)) {
		return ErrSignUpRateLimited
	}
	return nil
}
