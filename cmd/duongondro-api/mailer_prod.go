//go:build !DEV

package main

import (
	"log/slog"
	"os"
	"strconv"

	"github.com/Duongondro/duongondro-api/internal/mail"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// mailer sends magic links over SMTP when MAIL_FROM is set (SMTP_HOST, SMTP_PORT,
// default 587, SMTP_USERNAME and SMTP_PASSWORD: Brevo's relay in production);
// without it the magic-link endpoints answer that they are not configured.
func mailer() (service.Mailer, error) {
	from := os.Getenv("MAIL_FROM")
	if from == "" {
		return nil, nil
	}
	if err := required("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"); err != nil {
		return nil, err
	}
	port := 587
	if p := os.Getenv("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		port = n
	}
	m, err := mail.NewSMTP(os.Getenv("SMTP_HOST"), port, os.Getenv("SMTP_USERNAME"), os.Getenv("SMTP_PASSWORD"), from)
	if err != nil {
		return nil, err
	}
	slog.Info("magic links by SMTP", "host", os.Getenv("SMTP_HOST"))
	return m, nil
}
