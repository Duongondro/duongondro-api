package server

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/web"
)

// serveWebsite answers the website's hosts before routing: the canonical host gets
// the embedded site (landing page, privacy policy, and the invite, add-friend and
// magic-link pages a browser shows when the app is not installed), the others a
// permanent redirect to it. No API route is reachable on them; only the association
// files under /.well-known/ go on to the router, which generates them. The
// download count beacon (POST /download/<platform>/count) counts in q.
func serveWebsite(e *echo.Echo, hosts []string, q *db.Queries) {
	if len(hosts) == 0 {
		return
	}
	canonical := strings.ToLower(hosts[0])
	known := map[string]bool{}
	for _, h := range hosts {
		known[strings.ToLower(h)] = true
	}
	site := web.Handler(downloads{q})
	serveSite := func(c *echo.Context) error {
		site.ServeHTTP(c.Response(), c.Request())
		return nil
	}
	// The download count beacon is the website's only write: limit it per client
	// address so one script cannot inflate the total. The limiter forgets an
	// address a minute after its last request.
	serveSite = rateLimit(func(r *http.Request) bool {
		return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/download/")
	}, downloadRateLimit)(serveSite)
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()
			host := requestHost(r)
			switch {
			case !known[host]:
				return next(c)
			case host != canonical:
				return c.Redirect(http.StatusMovedPermanently, "https://"+canonical+r.URL.RequestURI())
			case strings.HasPrefix(r.URL.Path, "/.well-known/"):
				return next(c)
			}
			return serveSite(c)
		}
	})
}

func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// downloads keeps the website's download totals: single-table work, so sqlc
// directly.
type downloads struct{ q *db.Queries }

func (d downloads) Count(ctx context.Context, platform string) error {
	return d.q.CountDownload(ctx, platform)
}

func (d downloads) Total(ctx context.Context, platform string) (int64, error) {
	return d.q.DownloadTotal(ctx, platform)
}
