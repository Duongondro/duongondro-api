//go:build !DEV

package server

import (
	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/auth"
)

// registerDevSession does nothing without the DEV build tag: signing in without a
// sign-in method is for local development only (see dev_session_dev.go).
func registerDevSession(*echo.Echo, *auth.Service) {}
