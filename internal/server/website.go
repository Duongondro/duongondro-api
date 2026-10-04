package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/web"
)

// serveWebsite answers the website's hosts before routing: the canonical host gets
// the embedded site (landing page, privacy policy, and the invite, add-friend and
// magic-link pages a browser shows when the app is not installed), the others a
// permanent redirect to it. No API route is reachable on them; only the association
// files under /.well-known/ go on to the router, which generates them.
func serveWebsite(e *echo.Echo, hosts []string) {
	if len(hosts) == 0 {
		return
	}
	canonical := strings.ToLower(hosts[0])
	known := map[string]bool{}
	for _, h := range hosts {
		known[strings.ToLower(h)] = true
	}
	site := web.Handler()
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
			site.ServeHTTP(c.Response(), r)
			return nil
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
