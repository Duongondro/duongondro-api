//go:build DEV

package server

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/Duongondro/duongondro-api/internal/auth"
)

// devSessionPath signs in without any sign-in method. Development builds only.
const devSessionPath = "/api/dev/session"

// registerDevSession adds POST /api/dev/session[?user=<id>], which signs in as that
// user, or as a new one without the parameter, and answers {"token", "userId"}: the
// Simulator and the emulator use it against a local server until passkeys and Sign in
// with Apple are set up.
//
// Compiled only with the DEV build tag (make serve sets it) and registered directly on
// Echo rather than in api/openapi.yaml, so a plain build contains no trace of it:
// forgetting a tag fails safe. dev_session_prod.go registers nothing, and
// cmd/duongondro-api's TestReleaseBinaryHasNoDevSession checks the built binary.
func registerDevSession(e *echo.Echo, svc *auth.Service) {
	e.POST(devSessionPath, func(c *echo.Context) error {
		token, id, err := svc.DevSession(c.Request().Context(), c.QueryParam("user"))
		if errors.Is(err, auth.ErrNoSuchUser) {
			return c.JSON(http.StatusNotFound, map[string]any{"error": err.Error()})
		} else if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]any{"token": token, "userId": id.String()})
	})
}
