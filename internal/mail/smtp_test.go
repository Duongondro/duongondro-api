package mail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"

	gomail "github.com/wneessen/go-mail"
)

func TestSendMagicLink(t *testing.T) {
	var sent *gomail.Msg
	s := &SMTP{From: "Duongöndro <sign-in@duongondro.app>", send: func(_ context.Context, m *gomail.Msg) error {
		sent = m
		return nil
	}}
	link := "https://duongondro.app/m#TOKEN"
	if err := s.SendMagicLink(t.Context(), "bo@example.com", link, "7K2M Q9XA"); err != nil {
		t.Fatal(err)
	}
	rcpts, err := sent.GetRecipients()
	if err != nil || len(rcpts) != 1 || rcpts[0] != "<bo@example.com>" {
		t.Fatalf("recipients %v, %v", rcpts, err)
	}
	var raw bytes.Buffer
	if _, err := sent.WriteTo(&raw); err != nil {
		t.Fatal(err)
	}
	head, encoded, _ := strings.Cut(raw.String(), "\r\n\r\n")
	if !strings.Contains(head, "sign-in@duongondro.app") || !strings.Contains(head, "Subject: ") {
		t.Fatalf("headers:\n%s", head)
	}
	text, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encoded)))
	if err != nil || !strings.Contains(string(text), link) || !strings.Contains(string(text), "7K2M Q9XA") {
		t.Fatalf("body lacks the link or code (%v):\n%s", err, text)
	}
}

func TestSendEmailConfirmation(t *testing.T) {
	var sent *gomail.Msg
	s := &SMTP{From: "sign-in@duongondro.app", send: func(_ context.Context, m *gomail.Msg) error {
		sent = m
		return nil
	}}
	link := "https://duongondro.app/m/e#TOKEN"
	if err := s.SendEmailConfirmation(t.Context(), "bo@example.com", link, "7K2M Q9XA"); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if _, err := sent.WriteTo(&raw); err != nil {
		t.Fatal(err)
	}
	_, encoded, _ := strings.Cut(raw.String(), "\r\n\r\n")
	text, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encoded)))
	body := strings.ReplaceAll(string(text), "\r\n", "\n")
	if err != nil || !strings.Contains(body, "confirm this address for your Duongöndro account") ||
		!strings.Contains(body, "type this code in the app:\n\n    7K2M Q9XA\n") {
		t.Fatalf("body lacks the code or wording (%v):\n%s", err, body)
	}
	// No 0.4 app opens the link, so the mail does not offer it yet.
	if strings.Contains(body, link) || strings.Contains(body, "#TOKEN") || strings.Contains(body, "http") {
		t.Fatalf("the confirmation mail offers a link:\n%s", body)
	}
}

func TestBadAddressIsRefused(t *testing.T) {
	s := &SMTP{From: "sign-in@duongondro.app", send: func(context.Context, *gomail.Msg) error {
		t.Fatal("sent")
		return nil
	}}
	if err := s.SendMagicLink(t.Context(), "not an address", "x", "y"); err == nil {
		t.Fatal("no error")
	}
}

// A failure never carries the relay's text or the parser's, which can quote the
// address; only what MailStatus describes.
func TestErrorsOmitTheAddress(t *testing.T) {
	s := &SMTP{From: "sign-in@duongondro.app", send: func(context.Context, *gomail.Msg) error {
		return errors.New("550 5.1.1 <secret.person@example.com>: Recipient address rejected")
	}}
	for _, to := range []string{"secret.person@example.com", "secret.person@example.com <secret.person@"} {
		err := s.SendEmailConfirmation(t.Context(), to, "x", "7K2M Q9XA")
		var me *Error
		if !errors.As(err, &me) || strings.Contains(err.Error(), "secret.person") || strings.Contains(me.MailStatus(), "secret.person") {
			t.Fatalf("%q: %v", to, err)
		}
	}
	err := s.SendMagicLink(t.Context(), "secret.person@example.com", "x", "y")
	if err == nil || strings.Contains(err.Error(), "secret.person") {
		t.Fatalf("magic link: %v", err)
	}
}
