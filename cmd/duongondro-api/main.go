// Command duongondro-api serves the Duongöndro API.
//
//	duongondro-api [serve]   serve on LISTEN_ADDR, else 127.0.0.1:PORT (the shared
//	                         server's env file sets PORT), else 127.0.0.1:8080; behind Caddy
//	duongondro-api migrate   apply the database migrations and exit
//	duongondro-api reapply-purges
//	                         after restoring a backup, delete again every account
//	                         purged since (only hashes of their ids are kept)
//	duongondro-api admit [-n 5] [-days 30]
//	                         print fresh single-use admission codes, the sign-up
//	                         gate for members nobody can invite (the first ones)
//
// DATABASE_URL is required for all of them. Migrations are not applied by serve: the
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
//	                   (default https://duongondro.app/m#, so the token stays in
//	                   the fragment and never reaches a server log)
//	WEB_HOSTS          hosts that serve the public website instead of the API,
//	                   canonical first: duongondro.app,www.duongondro.app
//	APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY_FILE
//	                   the Sign in with Apple key (.p8), to revoke authorisations when
//	                   an account is deleted; the first APPLE_CLIENT_IDS is the client
//	APNS_KEY_ID, APNS_PRIVATE_KEY_FILE, APNS_TOPIC
//	                   push to iOS (team: APPLE_TEAM_ID; topic: the bundle id)
//	FCM_SERVICE_ACCOUNT_FILE
//	                   push to Android: the Firebase service account's JSON key
//	MAIL_FROM, SMTP_HOST, SMTP_PORT, SMTP_LOGIN, SMTP_TOKEN
//	                   magic links by SMTP with STARTTLS (Brevo's relay; port default 587)
//	APPLE_APP_IDS      <team>.<bundle id> for apple-app-site-association
//	ANDROID_PACKAGE, ANDROID_CERT_SHA256
//	                   for assetlinks.json (fingerprints comma-separated)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/apple"
	"github.com/Duongondro/duongondro-api/internal/buildinfo"
	"github.com/Duongondro/duongondro-api/internal/migrate"
	"github.com/Duongondro/duongondro-api/internal/oidc"
	"github.com/Duongondro/duongondro-api/internal/push"
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
	case "reapply-purges":
		err = reapplyPurges(ctx)
	case "admit":
		err = admit(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (serve, migrate, reapply-purges or admit)", command)
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

func reapplyPurges(ctx context.Context) error {
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	n, err := service.NewGDPR(pool).ReapplyPurges(ctx)
	if err == nil {
		slog.Info("reapplied purges", "accounts", n)
	}
	return err
}

// admit prints n fresh admission codes, one per line in groups of four, valid for
// days days. Only their hashes are stored: the printout is the only copy.
func admit(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("admit", flag.ContinueOnError)
	n := flags.Int("n", 5, "how many codes to print (1 to 1000)")
	days := flags.Int("days", int(service.DefaultAdmissionLifetime/(24*time.Hour)), "days until the codes expire (1 to 365)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("admit takes no arguments, only -n and -days")
	}
	if *n < 1 || *n > 1000 {
		return fmt.Errorf("-n must be between 1 and 1000")
	}
	if *days < 1 || *days > 365 {
		return fmt.Errorf("-days must be between 1 and 365")
	}
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	codes, err := service.NewAdmissions(pool).Issue(ctx, *n, time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	for _, c := range codes {
		fmt.Println(service.FormatCode(c))
	}
	slog.Info("issued admission codes", "count", len(codes), "days", *days)
	return nil
}

// required fails startup when a key file is configured without the ids it needs, so a
// misconfiguration shows at once rather than as a warning on every push or revoke.
func required(names ...string) error {
	for _, n := range names {
		if os.Getenv(n) == "" {
			return fmt.Errorf("%s is required with the key file", n)
		}
	}
	return nil
}

func serve(ctx context.Context) error {
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		addr = "127.0.0.1:" + port
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	e, nudges, err := server.New(pool, cfg)
	if err != nil {
		return err
	}
	go nudges.Run(ctx)
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

func loadConfig() (server.Config, error) {
	rpID, origins := os.Getenv("RP_ID"), list("RP_ORIGINS")
	if rpID == "" || len(origins) == 0 {
		return server.Config{}, fmt.Errorf("RP_ID and RP_ORIGINS are required")
	}
	verifiers := map[string]service.TokenVerifier{}
	var revoker service.AppleRevoker
	if ids := list("APPLE_CLIENT_IDS"); len(ids) > 0 {
		verifiers["apple"] = oidc.Apple(ids)
		if file := os.Getenv("APPLE_PRIVATE_KEY_FILE"); file != "" {
			if err := required("APPLE_TEAM_ID", "APPLE_KEY_ID"); err != nil {
				return server.Config{}, err
			}
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
		base = "https://duongondro.app/m#"
	}
	mail, err := mailer()
	if err != nil {
		return server.Config{}, err
	}
	senders, err := pushSenders()
	if err != nil {
		return server.Config{}, err
	}
	return server.Config{
		SignIn: service.SignInConfig{RPID: rpID, RPOrigins: origins, Verifiers: verifiers, Mailer: mail,
			Apple: revoker},
		MagicLinkBase: base,
		Push:          senders,
		WellKnown: server.WellKnown{AppleAppIDs: list("APPLE_APP_IDS"), AndroidPackage: os.Getenv("ANDROID_PACKAGE"),
			AndroidFingerprints: list("ANDROID_CERT_SHA256")},
		WebHosts: list("WEB_HOSTS"),
	}, nil
}

// pushSenders configures APNs and FCM from the environment; either may be absent.
func pushSenders() (push.Senders, error) {
	senders := push.Senders{}
	client := &http.Client{Timeout: 15 * time.Second}
	if file := os.Getenv("APNS_PRIVATE_KEY_FILE"); file != "" {
		if err := required("APPLE_TEAM_ID", "APNS_KEY_ID", "APNS_TOPIC"); err != nil {
			return nil, err
		}
		p8, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		key, err := apple.ParseKey(p8)
		if err != nil {
			return nil, err
		}
		apns := &push.APNs{TeamID: os.Getenv("APPLE_TEAM_ID"), KeyID: os.Getenv("APNS_KEY_ID"), Topic: os.Getenv("APNS_TOPIC"),
			Key: key, HTTP: client, Now: time.Now,
			BaseURL: map[string]string{"apns": push.APNsProduction, "apns-sandbox": push.APNsSandbox}}
		senders["apns"], senders["apns-sandbox"] = apns, apns
	}
	if file := os.Getenv("FCM_SERVICE_ACCOUNT_FILE"); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var account struct {
			ProjectID   string `json:"project_id"`
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
		}
		if err := json.Unmarshal(raw, &account); err != nil {
			return nil, err
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(account.PrivateKey))
		if err != nil {
			return nil, err
		}
		senders["fcm"] = &push.FCM{ProjectID: account.ProjectID, ClientEmail: account.ClientEmail, Key: key,
			TokenURL: push.GoogleTokenURL, BaseURL: push.FCMBaseURL, HTTP: client, Now: time.Now}
	}
	return senders, nil
}
