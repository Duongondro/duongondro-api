// Package mail sends the magic-link and address-confirmation mails over SMTP with STARTTLS, through Brevo's
// relay in production (as homeosapiens-go does). The message is plain text and
// carries the link and its code, and nothing else about the account.
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

Or type this code in the app:

    %s

They work once, for 15 minutes, and only until you ask for another mail. If you
did not ask for this one, ignore it; nobody can sign in without the link or the
code.
`

const confirmSubject = "Confirm your e-mail for Duongöndro"

// confirmBody carries only the code: the 0.4 apps do not open the confirmation
// link (/m/e#<token>; iOS ignores it, Android takes it for a sign-in link and
// fails), so the mail leaves it out until they do. The server still accepts the
// token (POST /api/me/email/verify).
const confirmBody = `To confirm this address for your Duongöndro account, so you can sign in with
it, type this code in the app:

    %s

It works once, for 15 minutes, and only until you ask for another mail. If you
did not ask for this one, ignore it; nobody can add this address to an account
without the code.
`

func (s *SMTP) message(to, subject, text string) (*gomail.Msg, error) {
	m := gomail.NewMsg(gomail.WithEncoding(gomail.EncodingQP), gomail.WithCharset(gomail.CharsetUTF8))
	if err := m.From(s.From); err != nil {
		return nil, fmt.Errorf("mail from: %w", err)
	}
	if err := m.To(to); err != nil {
		return nil, fmt.Errorf("mail to: %w", err)
	}
	m.Subject(subject)
	m.SetBodyString(gomail.TypeTextPlain, text)
	return m, nil
}

func (s *SMTP) SendMagicLink(ctx context.Context, to, link, code string) error {
	return s.deliver(ctx, to, subject, fmt.Sprintf(body, link, code))
}

// SendEmailConfirmation mails the code that adds the address to an existing
// account (POST /api/me/email); the link is left out for now (confirmBody).
func (s *SMTP) SendEmailConfirmation(ctx context.Context, to, link, code string) error {
	return s.deliver(ctx, to, confirmSubject, fmt.Sprintf(confirmBody, code))
}

func (s *SMTP) deliver(ctx context.Context, to, subject, text string) error {
	m, err := s.message(to, subject, text)
	if err != nil {
		return err
	}
	if err := s.send(ctx, m); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}
