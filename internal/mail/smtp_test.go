package mail

import (
	"bytes"
	"context"
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
	if err := s.SendMagicLink(t.Context(), "bo@example.com", link); err != nil {
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
	if err != nil || !strings.Contains(string(text), link) {
		t.Fatalf("body lacks the link (%v):\n%s", err, text)
	}
}

func TestBadAddressIsRefused(t *testing.T) {
	s := &SMTP{From: "sign-in@duongondro.app", send: func(context.Context, *gomail.Msg) error {
		t.Fatal("sent")
		return nil
	}}
	if err := s.SendMagicLink(t.Context(), "not an address", "x"); err == nil {
		t.Fatal("no error")
	}
}
