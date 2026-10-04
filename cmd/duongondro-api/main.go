// Command duongondro-api serves the Duongöndro API.
//
//	duongondro-api [serve]   serve on LISTEN_ADDR (default 127.0.0.1:8080, behind Caddy)
//	duongondro-api migrate   apply the database migrations and exit
//
// DATABASE_URL is required for both. Migrations are not applied by serve: the
// service script runs migrate first, as in CodeShare.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/buildinfo"
	"github.com/Duongondro/duongondro-api/internal/migrate"
	"github.com/Duongondro/duongondro-api/internal/server"
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
	info := buildinfo.Read()
	slog.Info("listening", "addr", addr, "revision", info.Short)
	sc := echo.StartConfig{
		Address:         addr,
		GracefulTimeout: 10 * time.Second,
		HideBanner:      true,
		HidePort:        true,
	}
	return sc.Start(ctx, server.New(pool))
}
