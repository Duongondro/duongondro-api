package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bucket is a token bucket: capacity burst, refilled at rate per second.
type bucket struct {
	tokens float64
	last   time.Time
}

// limiter keeps one bucket per key in memory, as CodeShare does. State is
// lost on restart, which only ever loosens the limits for a moment.
type limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	now    func() time.Time
	m      map[string]*bucket
	sweeps int
}

func newLimiter(now func() time.Time, burst int, per time.Duration) *limiter {
	return &limiter{
		rate:  float64(burst) / per.Seconds(),
		burst: float64(burst),
		now:   now,
		m:     map[string]*bucket{},
	}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.m[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	l.sweeps++
	if l.sweeps >= 1024 {
		l.sweeps = 0
		l.sweep(now)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that would be full again, bounding memory.
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.m {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.m, k)
		}
	}
}

type limits struct {
	authIP      *limiter // magic-link request and verify, per client IP
	mailAddress *limiter // magic-link mails per address
	inviteIP    *limiter // invite fetch and redeem, per client IP
	inviteMake  *limiter // invite creation, per user
	reports     *limiter // reports, per user
}

func newLimits(now func() time.Time) *limits {
	return &limits{
		authIP:      newLimiter(now, 20, time.Minute),
		mailAddress: newLimiter(now, 5, time.Hour),
		inviteIP:    newLimiter(now, 30, time.Minute),
		inviteMake:  newLimiter(now, 20, time.Hour),
		reports:     newLimiter(now, 10, time.Hour),
	}
}

// clientIP is the peer address, or the last X-Forwarded-For entry when the
// peer is loopback (Caddy on the same host appends the real client), so the
// header cannot be spoofed to dodge a limit.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if fwd := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); fwd != nil {
				return fwd.String()
			}
		}
	}
	if ip == nil {
		return host
	}
	return ip.String()
}
