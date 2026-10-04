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

// rateLimitPrefix limits requests whose path starts with prefix, keyed by the
// client's address (only those Caddy appended to X-Forwarded-For are trusted), as
// CodeShare limits its auth routes.
func rateLimitPrefix(prefix string, l RateLimit) echo.MiddlewareFunc {
	limiter := middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c *echo.Context) bool { return !strings.HasPrefix(c.Request().URL.Path, prefix) },
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate: float64(l.Requests) / l.Per.Seconds(), Burst: l.Requests, ExpiresIn: l.Per,
		}),
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			return c.JSON(http.StatusTooManyRequests, map[string]any{"error": "too many requests; try again later"})
		},
	})
	return limiter
}
