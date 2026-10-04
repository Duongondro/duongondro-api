package mail

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

type fakeSES struct{ in *sesv2.SendEmailInput }

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.in = in
	return &sesv2.SendEmailOutput{}, nil
}

func TestSendMagicLink(t *testing.T) {
	fake := &fakeSES{}
	s := &SES{Client: fake, From: "Duongöndro <hello@duongondro.app>"}
	if err := s.SendMagicLink(t.Context(), "bo@example.com", "https://duongondro.app/m/TOKEN"); err != nil {
		t.Fatal(err)
	}
	if fake.in.Destination.ToAddresses[0] != "bo@example.com" || !strings.Contains(*fake.in.Content.Simple.Body.Text.Data, "https://duongondro.app/m/TOKEN") {
		t.Fatalf("message %+v", fake.in)
	}
}
