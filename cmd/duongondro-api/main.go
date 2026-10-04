// Command duongondro-api serves the Duongöndro API.
//
//	duongondro-api [serve]   serve on LISTEN_ADDR (default 127.0.0.1:8080, behind Caddy)
//	duongondro-api migrate   apply the database migrations and exit
//
// DATABASE_URL is required for both. Migrations are not applied by serve: the
// service script runs migrate first, as in CodeShare.
//
// serve also reads:
//
//	RP_ID              passkey relying party, the domain (duongondro.app)
//	RP_ORIGINS         origins clients assert, comma-separated: https://duongondro.app,
//	                   android:apk-key-hash:<hash of the signing certificate>
//	APPLE_CLIENT_IDS   bundle ids Sign in with Apple tokens may be for (optional)
//	GOOGLE_CLIENT_IDS  OAuth client ids Google tokens may be for (optional)
//	MAGIC_LINK_BASE    URL a magic link's token is appended to
//	                   (default https://duongondro.app/m/)
//	APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY_FILE
//	                   the Sign in with Apple key (.p8), to revoke authorisations when
//	                   an account is deleted; the first APPLE_CLIENT_IDS is the client
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/apple"
	"github.com/Duongondro/duongondro-api/internal/buildinfo"
	"github.com/Duongondro/duongondro-api/internal/migrate"
	"github.com/Duongondro/duongondro-api/internal/oidc"
	"github.com/Duongondro/duongondro-api/internal/server"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	var err error
	switch command {
	case "serve":
		err = serve(ctx)
	case "migrate":
		err = runMigrate(ctx)
	default:
		err = fmt.Errorf("unknown command %q (serve or migrate)", command)
	}
	if err != nil {
		slog.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func openPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}
	// Connects lazily: serve starts, and answers /healthz, without a database.
	return pgxpool.New(ctx, dsn)
}

func runMigrate(ctx context.Context) error {
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	return migrate.Up(ctx, pool)
}

func serve(ctx context.Context) error {
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	cfg, err := config()
	if err != nil {
		return err
	}
	e, err := server.New(pool, cfg)
	if err != nil {
		return err
	}
	info := buildinfo.Read()
	slog.Info("listening", "addr", addr, "revision", info.Short)
	sc := echo.StartConfig{
		Address:         addr,
		GracefulTimeout: 10 * time.Second,
		HideBanner:      true,
		HidePort:        true,
	}
	return sc.Start(ctx, e)
}

func list(env string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(env), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func config() (server.Config, error) {
	rpID, origins := os.Getenv("RP_ID"), list("RP_ORIGINS")
	if rpID == "" || len(origins) == 0 {
		return server.Config{}, fmt.Errorf("RP_ID and RP_ORIGINS are required")
	}
	verifiers := map[string]service.TokenVerifier{}
	var revoker service.AppleRevoker
	if ids := list("APPLE_CLIENT_IDS"); len(ids) > 0 {
		verifiers["apple"] = oidc.Apple(ids)
		if file := os.Getenv("APPLE_PRIVATE_KEY_FILE"); file != "" {
			p8, err := os.ReadFile(file)
			if err != nil {
				return server.Config{}, err
			}
			key, err := apple.ParseKey(p8)
			if err != nil {
				return server.Config{}, err
			}
			revoker = &apple.Client{TeamID: os.Getenv("APPLE_TEAM_ID"), KeyID: os.Getenv("APPLE_KEY_ID"), ClientID: ids[0],
				Key: key, BaseURL: apple.DefaultBaseURL, HTTP: &http.Client{Timeout: 10 * time.Second}, Now: time.Now}
		}
	}
	if ids := list("GOOGLE_CLIENT_IDS"); len(ids) > 0 {
		verifiers["google"] = oidc.Google(ids)
	}
	base := os.Getenv("MAGIC_LINK_BASE")
	if base == "" {
		base = "https://duongondro.app/m/"
	}
	return server.Config{
		SignIn: service.SignInConfig{RPID: rpID, RPOrigins: origins, Verifiers: verifiers, Mailer: mailer(),
			Apple: revoker},
		MagicLinkBase: base,
	}, nil
}
