package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"
	echomiddleware "github.com/labstack/echo/v5/middleware"
)

// defaultErrorHandler writes the response: echo's JSON body, {"message": ...}, without
// the error itself, which could carry database details.
var defaultErrorHandler = echo.DefaultHTTPErrorHandler(false)

// errorHandledKey marks, in the echo context, a request whose error was handled.
const errorHandledKey = "duongondro.errorHandled"

// ErrorHandler answers errors as echo does, and logs unexpected (5xx) errors at level
// ERROR, once each: ERROR is reserved for what needs a human (CodeShare's rule, where
// CloudWatch e-mails every such event). Expected failures (a 4xx, such as a bad
// signature or a 401 for a bogus session token) are answered without a log line
// here; the request logger records them at level INFO.
//
// Each error reaches it twice: requestLogger (HandleError) calls it to get the status
// it logs, and returns the error on to echo, which calls it again. medic-go's
// handlers.ErrorHandler returns early once the response is committed; this one
// remembers the request was handled instead, so that it still logs an error whose
// response was committed before it failed, such as a panic after writing.
func ErrorHandler(c *echo.Context, err error) {
	if c.Get(errorHandledKey) != nil {
		return
	}
	c.Set(errorHandledKey, true)

	if isUnstorableText(err) {
		slog.WarnContext(c.Request().Context(), "Request rejected by the database",
			"method", c.Request().Method,
			"path", c.Request().URL.Path,
			"request_id", c.Response().Header().Get(echo.HeaderXRequestID),
			"error", err.Error(),
		)
		defaultErrorHandler(c, echo.ErrBadRequest)
		return
	}

	status := http.StatusInternalServerError
	var coder echo.HTTPStatusCoder
	if errors.As(err, &coder) && coder.StatusCode() != 0 {
		status = coder.StatusCode()
	}
	if status >= http.StatusInternalServerError {
		logRequestError(c, err)
	}
	defaultErrorHandler(c, err)
}

// pgCharacterNotInRepertoire is SQLSTATE 22021: text that isn't valid UTF-8, or
// contains a NUL. See https://www.postgresql.org/docs/current/errcodes-appendix.html.
const pgCharacterNotInRepertoire = "22021"

// isUnstorableText reports whether Postgres refused a parameter as text. Only a client
// sends such bytes; handlers should reject them first (auth.ValidText), and this
// catches any they miss, as a 400 at level WARN rather than an ERROR.
func isUnstorableText(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == pgCharacterNotInRepertoire
}

// logRequestError logs an unexpected error. Recovered panics are logged as a
// separate "panic" event with the stack trace as its own attribute, so that
// in production, where logs are JSON lines, they can be found with the filter
// pattern { $.msg = "panic" }.
//
// Only the path is logged, never the query string, which can carry sign-in
// codes, cursors and ids.
func logRequestError(c *echo.Context, err error) {
	attrs := []any{
		"method", c.Request().Method,
		"path", c.Request().URL.Path,
		"request_id", c.Response().Header().Get(echo.HeaderXRequestID),
	}

	// With the request's context, the events carry the IDs of its trace
	reqCtx := c.Request().Context()
	if panicErr, ok := errors.AsType[*echomiddleware.PanicStackError](err); ok {
		slog.ErrorContext(reqCtx, "panic", append(attrs, "error", panicErr.Err.Error(), "stack", string(panicErr.Stack))...)
		return
	}
	// A client that hung up (the app sent to the background, a lost connection)
	// cancels the request's queries: nothing to wake anyone up for.
	if errors.Is(err, context.Canceled) && reqCtx.Err() != nil {
		slog.WarnContext(reqCtx, "Request canceled", append(attrs, "error", err.Error())...)
		return
	}
	slog.ErrorContext(reqCtx, "Request failed", append(attrs, "error", err.Error())...)
}

// requestLogger logs every request at level INFO. Errors that need
// attention are logged at level ERROR by ErrorHandler, once each: the default
// echo logger would log every returned error at level ERROR, and duplicate each
// 500. Only the path is logged, never the query string, which can carry sign-in
// codes, cursors and ids.
func requestLogger() echo.MiddlewareFunc {
	return echomiddleware.RequestLoggerWithConfig(echomiddleware.RequestLoggerConfig{
		LogLatency:   true,
		LogRemoteIP:  true,
		LogHost:      true,
		LogMethod:    true,
		LogURIPath:   true,
		LogRequestID: true,
		LogUserAgent: true,
		LogStatus:    true,
		HandleError:  true,
		LogValuesFunc: func(c *echo.Context, v echomiddleware.RequestLoggerValues) error {
			attrs := []slog.Attr{
				slog.String("method", v.Method),
				slog.String("path", v.URIPath),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("host", v.Host),
				slog.String("user_agent", v.UserAgent),
				slog.String("remote_ip", v.RemoteIP),
				slog.String("request_id", v.RequestID),
			}
			// Server errors are logged in full by ErrorHandler
			if v.Error != nil && v.Status < 500 {
				attrs = append(attrs, slog.String("error", v.Error.Error()))
			}
			c.Logger().LogAttrs(c.Request().Context(), slog.LevelInfo, "REQUEST", attrs...)
			return nil
		},
	})
}
