// Package mail sends the magic-link and address-confirmation mails over SMTP with STARTTLS, through Brevo's
// relay in production (as homeosapiens-go does). The message is plain text and
// carries the link and its code, and nothing else about the account.
package mail

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// Error is a failed delivery reduced to what may be logged. The relay's reply
// text (a rejected RCPT quotes the recipient) and the parser's errors can carry
// the address, so neither is kept: only the stage, the SMTP reply code and
// enhanced status, and go-mail's fixed reason.
type Error struct {
	Stage     string // "recipient" (the address did not parse), "network", "timeout" or "send"
	Reason    string // go-mail's fixed reason, such as "failed to set RCPT TO address"
	Code      int    // the relay's SMTP reply code; 0 if it gave none
	Enhanced  string // the relay's enhanced status code (RFC 2034), if any
	Temporary bool
}

func (e *Error) Error() string { return "smtp: " + e.MailStatus() }

// MailStatus describes the failure without the relay's text or the address.
func (e *Error) MailStatus() string {
	out := e.Stage
	if e.Reason != "" {
		out += ": " + e.Reason
	}
	if e.Code != 0 {
		out += fmt.Sprintf(" (%d %s)", e.Code, e.Enhanced)
	}
	if e.Temporary {
		out += ", temporary"
	}
	return out
}

func classify(err error) *Error {
	if se, ok := errors.AsType[*gomail.SendError](err); ok {
		return &Error{Stage: "send", Reason: se.Reason.String(), Code: se.ErrorCode(), Enhanced: se.EnhancedStatusCode(), Temporary: se.IsTemp()}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Stage: "timeout", Temporary: true}
	}
	if _, ok := errors.AsType[net.Error](err); ok {
		return &Error{Stage: "network", Temporary: true}
	}
	return &Error{Stage: "send"}
}

func (s *SMTP) deliver(ctx context.Context, to, subject, text string) error {
	m, err := s.message(to, subject, text)
	if err != nil {
		return &Error{Stage: "recipient"}
	}
	if err := s.send(ctx, m); err != nil {
		return classify(err)
	}
	return nil
}
