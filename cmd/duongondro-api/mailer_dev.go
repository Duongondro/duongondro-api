//go:build DEV

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Duongondro/duongondro-api/internal/service"
)

// mailer prints magic links to stderr in DEV builds, so the Simulator can sign in
// against a local server. Never in a release build: the link is a credential.
func mailer() service.Mailer { return stderrMailer{} }

type stderrMailer struct{}

func (stderrMailer) SendMagicLink(_ context.Context, to, link string) error {
	_, err := fmt.Fprintf(os.Stderr, "DEV magic link for %s: %s\n", to, link)
	return err
}
