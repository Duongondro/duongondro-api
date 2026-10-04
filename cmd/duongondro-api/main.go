// Command duongondro-api serves the Duongöndro API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Duongondro/duongondro-api/internal/buildinfo"
	"github.com/Duongondro/duongondro-api/internal/server"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080" // behind Caddy, as CodeShare
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.New(log),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	info := buildinfo.Read()
	log.Info("listening", "addr", addr, "revision", info.Short)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
