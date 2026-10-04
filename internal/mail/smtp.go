// Package mail sends the magic-link mail over SMTP with STARTTLS, through Brevo's
// relay in production (as homeosapiens-go does). The message is plain text and
// carries the link and nothing else about the account.
package mail

import (
	"context"
	"fmt"
	"time"

	gomail "github.com/wneessen/go-mail"
)

// SMTP sends through one authenticated relay.
type SMTP struct {
	// From is a sender on duongondro.app that the relay has verified; it must also be
	// registered with Apple, or "Hide My Email" relay addresses refuse the mail.
	From string
	// send delivers a message; DialAndSendWithContext on a client in production.
	send func(context.Context, *gomail.Msg) error
}

// NewSMTP returns a mailer for host:port that authenticates with username and
// password and refuses to send without TLS.
func NewSMTP(host string, port int, username, password, from string) (*SMTP, error) {
	client, err := gomail.NewClient(host,
		gomail.WithPort(port),
		gomail.WithTLSPolicy(gomail.TLSMandatory),
		gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
		gomail.WithUsername(username),
		gomail.WithPassword(password),
		gomail.WithTimeout(20*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return &SMTP{From: from, send: func(ctx context.Context, m *gomail.Msg) error {
		return client.DialAndSendWithContext(ctx, m)
	}}, nil
}

const subject = "Sign in to Duongöndro"

// body is English for now: the server keeps no language preference, and phones
// render pushes themselves; a localised mail needs the app to send its language.
const body = `Tap the link on your phone to sign in to Duongöndro:

%s

It works once, for 15 minutes. If you did not ask for it, ignore this mail;
nobody can sign in without the link.
`

func (s *SMTP) message(to, link string) (*gomail.Msg, error) {
	m := gomail.NewMsg(gomail.WithEncoding(gomail.EncodingQP), gomail.WithCharset(gomail.CharsetUTF8))
	if err := m.From(s.From); err != nil {
		return nil, fmt.Errorf("mail from: %w", err)
	}
	if err := m.To(to); err != nil {
		return nil, fmt.Errorf("mail to: %w", err)
	}
	m.Subject(subject)
	m.SetBodyString(gomail.TypeTextPlain, fmt.Sprintf(body, link))
	return m, nil
}

func (s *SMTP) SendMagicLink(ctx context.Context, to, link string) error {
	m, err := s.message(to, link)
	if err != nil {
		return err
	}
	if err := s.send(ctx, m); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}
