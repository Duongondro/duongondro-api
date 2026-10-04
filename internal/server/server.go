// Package server implements api.StrictServerInterface: it authenticates, maps DTOs
// and errors, and leaves the rules to internal/service.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/buildinfo"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/push"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// bodyLimit caps every request body. A sealed log is at most about 16 KiB.
const bodyLimit = 64 << 10

type Server struct {
	auth     *auth.Service
	accounts *service.Accounts
	devices  *service.Devices
	wraps    *service.Wraps
	logs     *service.Logs
	recovery *service.Recovery
	social   *service.Social
	gdpr     *service.GDPR
	signIn   *service.SignIn
	nudges   *service.Nudges
	version  buildinfo.Info

	clientErrors *service.ClientErrors

	magicLinkBase string
}

// Config carries what the sign-in methods need from the environment.
type Config struct {
	SignIn service.SignInConfig
	// MagicLinkBase is prefixed to a magic link's token: an App Link and Universal
	// Link on duongondro.app that opens the app.
	MagicLinkBase string
	// Push delivers nudges (APNs and FCM); nil sends nothing.
	Push push.Sender
	// WellKnown is served on the apex for Universal Links, App Links and passkeys.
	WellKnown WellKnown
}

var _ api.StrictServerInterface = (*Server)(nil)

// New returns an Echo instance serving the API, and the nudge sender, whose Run the
// caller starts alongside it.
func New(pool *pgxpool.Pool, cfg Config) (*echo.Echo, *service.Nudges, error) {
	e := echo.NewWithConfig(echo.Config{
		Logger: slog.Default(),
		// Caddy, on loopback, appends the client's address to X-Forwarded-For;
		// only addresses it added are trusted.
		IPExtractor: echo.ExtractIPFromXFFHeader(echo.TrustLinkLocal(false), echo.TrustPrivateNet(false)),
	})
	e.HTTPErrorHandler = ErrorHandler
	e.Use(middleware.RequestID())
	e.Use(requestLogger())
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{StackSize: 64 << 10, DisableStackAll: true}))
	e.Use(middleware.BodyLimit(bodyLimit))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
			return next(c)
		}
	})

	devices := service.NewDevices(pool)
	authSvc := auth.New(pool)
	social := service.NewSocial(pool)
	signIn, err := service.NewSignIn(pool, authSvc, social, cfg.SignIn)
	if err != nil {
		return nil, nil, err
	}
	s := &Server{
		auth:     authSvc,
		accounts: service.NewAccounts(pool),
		devices:  devices,
		wraps:    service.NewWraps(pool, devices),
		logs:     service.NewLogs(pool),
		recovery: service.NewRecovery(pool),
		social:   social,
		gdpr:     service.NewGDPR(pool),
		signIn:   signIn,
		nudges:   service.NewNudges(pool, cfg.Push),
		version:  buildinfo.Read(),

		clientErrors: service.NewClientErrors(nil, service.ClientErrorLimit, service.ClientErrorWindow),

		magicLinkBase: cfg.MagicLinkBase,
	}
	// Invites and sign-in are reachable without a session: limit them per address, so
	// invite ids cannot be guessed and sign-ups cannot be scripted (design: Social).
	e.Use(rateLimitPrefix("/api/invites", inviteRateLimit))
	e.Use(rateLimitPrefix("/api/auth/", authRateLimit))
	registerWellKnown(e, cfg.WellKnown)
	// Sign-in without any method; only in DEV builds.
	registerDevSession(e, s.auth)
	api.RegisterHandlers(e, api.NewStrictHandler(s, nil))
	return e, s.nudges, nil
}

// authenticate resolves the Authorization header to its user. ok is false for a
// missing or invalid token (answer 401); err is the server's.
func (s *Server) authenticate(ctx context.Context, header string) (user db.User, ok bool, err error) {
	token, ok := auth.BearerPrefix(header)
	if !ok {
		return db.User{}, false, nil
	}
	user, err = s.auth.SessionUser(ctx, token)
	if errors.Is(err, auth.ErrInvalidToken) {
		return db.User{}, false, nil
	} else if err != nil {
		return db.User{}, false, err
	}
	return user, true, nil
}

func errorBody(err error) api.Error { return api.Error{Error: err.Error()} }

// clientError sorts a service error into the response kinds every handler shares;
// ok is false for anything else, which the handler returns as a 500.
func clientError(err error) (kind int, body api.Error, ok bool) {
	if v, is := errors.AsType[*service.ValidationError](err); is {
		return http.StatusBadRequest, errorBody(v), true
	}
	if v, is := errors.AsType[*service.ConflictError](err); is {
		return http.StatusConflict, errorBody(v), true
	}
	if errors.Is(err, service.ErrNotFound) {
		return http.StatusNotFound, errorBody(err), true
	}
	return 0, api.Error{}, false
}

func (s *Server) GetHealth(context.Context, api.GetHealthRequestObject) (api.GetHealthResponseObject, error) {
	return api.GetHealth200TextResponse("ok\n"), nil
}

func (s *Server) GetVersion(context.Context, api.GetVersionRequestObject) (api.GetVersionResponseObject, error) {
	v := api.GetVersion200JSONResponse{Revision: s.version.Revision, Short: s.version.Short, Modified: s.version.Modified, Go: s.version.Go}
	if s.version.Time != "" {
		v.Time = &s.version.Time
	}
	return v, nil
}
