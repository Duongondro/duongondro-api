package server

import (
	"context"
	"log/slog"
)

// EmailSender delivers sign-in links. The production implementation (SES in
// an EU region) is a TODO in docs/stack.md.
type EmailSender interface {
	SendMagicLink(ctx context.Context, to, link string) error
}

// LogSender records only that a link was sent: never the address or the
// link, which signs its holder in.
type LogSender struct{ Log *slog.Logger }

func (l LogSender) SendMagicLink(ctx context.Context, to, link string) error {
	l.Log.Info("magic link sent (not delivered: no mail transport configured)")
	return nil
}

// SignInWithAppleRevoker revokes a user's Sign in with Apple token when the
// account is purged, through Apple's REST API.
type SignInWithAppleRevoker interface {
	Revoke(ctx context.Context, subject string) error
}

// NoopRevoker is used until Sign in with Apple exists.
type NoopRevoker struct{}

func (NoopRevoker) Revoke(ctx context.Context, subject string) error { return nil }
