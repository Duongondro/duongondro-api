package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// RateLimit allows Requests per Per, per client address, with a burst of Requests.
type RateLimit struct {
	Requests int
	Per      time.Duration
}

// inviteRateLimit covers fetching and redeeming invites, and creating them.
var inviteRateLimit = RateLimit{Requests: 30, Per: time.Minute}

// authRateLimit covers the sign-in routes, as CodeShare's limits its own.
var authRateLimit = RateLimit{Requests: 20, Per: time.Minute}

// profileRateLimit covers PATCH /api/me, whose 409 for a taken username would
// otherwise let an account probe which usernames exist.
var profileRateLimit = RateLimit{Requests: 10, Per: time.Minute}

// downloadRateLimit covers the website's download count beacon: a person clicks
// the button a few times at most.
var downloadRateLimit = RateLimit{Requests: 10, Per: time.Minute}

// rateLimitPrefix limits requests whose path starts with prefix, keyed by the
// client's address (only those Caddy appended to X-Forwarded-For are trusted), as
// CodeShare limits its auth routes.
func rateLimitPrefix(prefix string, l RateLimit) echo.MiddlewareFunc {
	return rateLimit(func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, prefix) }, l)
}

// rateLimitRoute limits one method on one exact path, keyed by client address.
func rateLimitRoute(method, path string, l RateLimit) echo.MiddlewareFunc {
	return rateLimit(func(r *http.Request) bool { return r.Method == method && r.URL.Path == path }, l)
}

func rateLimit(applies func(*http.Request) bool, l RateLimit) echo.MiddlewareFunc {
	limiter := middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c *echo.Context) bool { return !applies(c.Request()) },
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate: float64(l.Requests) / l.Per.Seconds(), Burst: l.Requests, ExpiresIn: l.Per,
		}),
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			return c.JSON(http.StatusTooManyRequests, map[string]any{"error": "too many requests; try again later"})
		},
	})
	return limiter
}
