//go:build !DEV

package main

import "github.com/Duongondro/duongondro-api/internal/service"

// mailer is nil until SES in an EU region is set up (design: Backend and sync); the
// magic-link endpoints then answer that they are not configured.
func mailer() service.Mailer { return nil }
