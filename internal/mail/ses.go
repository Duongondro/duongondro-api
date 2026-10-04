// Package mail sends the magic-link mail through Amazon SES in an EU region, as the
// design says (the AWS account exists for CodeShare). The message is plain text and
// carries the link and nothing else about the account.
package mail

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// API is the part of the SES client used here, so tests can fake it.
type API interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

type SES struct {
	Client API
	// From is a verified sender on duongondro.app; it must also be registered with
	// Apple, or "Hide My Email" relay addresses refuse the mail.
	From string
}

const subject = "Sign in to Duongöndro"

// body is English for now: the server keeps no language preference, and phones
// render pushes themselves; a localised mail needs the app to send its language.
const body = `Tap the link on your phone to sign in to Duongöndro:

%s

It works once, for 15 minutes. If you did not ask for it, ignore this mail;
nobody can sign in without the link.
`

func (s *SES) SendMagicLink(ctx context.Context, to, link string) error {
	_, err := s.Client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(s.From),
		Destination:      &types.Destination{ToAddresses: []string{to}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String(subject), Charset: aws.String("UTF-8")},
			Body:    &types.Body{Text: &types.Content{Data: aws.String(fmt.Sprintf(body, link)), Charset: aws.String("UTF-8")}},
		}},
	})
	if err != nil {
		return fmt.Errorf("ses: %w", err)
	}
	return nil
}
