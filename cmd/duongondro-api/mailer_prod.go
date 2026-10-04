//go:build !DEV

package main

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"

	"github.com/Duongondro/duongondro-api/internal/mail"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// mailer sends magic links through SES when MAIL_FROM is set (region MAIL_REGION,
// default eu-central-1, credentials from the AWS default chain); without it the
// magic-link endpoints answer that they are not configured.
func mailer() service.Mailer {
	from := os.Getenv("MAIL_FROM")
	if from == "" {
		return nil
	}
	region := os.Getenv("MAIL_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil
	}
	return &mail.SES{Client: sesv2.NewFromConfig(cfg), From: from}
}
