package service

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"uuid"
)

// Limits of a client error report (see ClientErrorReport in api/openapi.yaml), in bytes.
// Ported from CodeShare.
const (
	MaxClientErrorMessage      = 2048
	MaxClientErrorVersion      = 64
	MaxClientErrorContext      = 20
	MaxClientErrorContextKey   = 64
	MaxClientErrorContextValue = 256
)

// Client error reports a user may send per window before they're refused.
const (
	ClientErrorLimit  = 30
	ClientErrorWindow = time.Hour
)

// ErrReportsRateLimited: the user sent too many reports in the current window (429).
var ErrReportsRateLimited = errors.New("too many reports; try again later")

// A ClientErrorReport is a crash or an error the app reports about itself.
type ClientErrorReport struct {
	Crash      bool // a crash (level ERROR); otherwise an error (WARN), such as a device-key fallback
	Message    string
	AppVersion string
	OSVersion  string
	Context    map[string]string
}

// ClientErrors turns reports from the app into log records, one each, with the
// reporter's user id and nothing else about them, and limits how many a user may
// send. Nothing is stored. The limit is kept in memory: a restart resets it, which
// is fine for a small app: it only keeps one client from flooding the log.
type ClientErrors struct {
	logger *slog.Logger // nil: slog.Default() at the time of logging
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	windows map[uuid.UUID]*reportWindow
}

type reportWindow struct {
	start time.Time
	count int
}

// NewClientErrors logs reports to logger (nil: the default logger), allowing each
// user limit reports per window.
func NewClientErrors(logger *slog.Logger, limit int, window time.Duration) *ClientErrors {
	return &ClientErrors{logger: logger, limit: limit, window: window, now: time.Now,
		windows: map[uuid.UUID]*reportWindow{}}
}

// SetClock replaces the clock the rate limit uses (for tests).
func (c *ClientErrors) SetClock(now func() time.Time) { c.now = now }

// Report validates r and logs it for userID: a *ValidationError for a report that
// breaks the size limits, ErrReportsRateLimited beyond the user's limit. Only valid reports
// count towards the limit.
func (c *ClientErrors) Report(ctx context.Context, userID uuid.UUID, r ClientErrorReport) error {
	if err := r.validate(); err != nil {
		return err
	}
	if !c.allow(userID) {
		return ErrReportsRateLimited
	}

	keys := make([]string, 0, len(r.Context))
	for k := range r.Context {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	contextAttrs := make([]any, 0, len(keys))
	for _, k := range keys {
		contextAttrs = append(contextAttrs, slog.String(k, r.Context[k]))
	}

	level, msg, kind := slog.LevelWarn, "Client error", "error"
	if r.Crash {
		level, msg, kind = slog.LevelError, "Client crash", "crash"
	}
	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Log(ctx, level, msg,
		"user_id", userID.String(),
		"kind", kind,
		"report", r.Message,
		"app_version", r.AppVersion,
		"os_version", r.OSVersion,
		slog.Group("context", contextAttrs...),
	)
	return nil
}

func (r ClientErrorReport) validate() error {
	switch {
	case r.Message == "":
		return invalid("message is required")
	case len(r.Message) > MaxClientErrorMessage:
		return invalid("message is longer than %d bytes", MaxClientErrorMessage)
	case len(r.AppVersion) > MaxClientErrorVersion:
		return invalid("appVersion is longer than %d bytes", MaxClientErrorVersion)
	case len(r.OSVersion) > MaxClientErrorVersion:
		return invalid("osVersion is longer than %d bytes", MaxClientErrorVersion)
	case len(r.Context) > MaxClientErrorContext:
		return invalid("context has more than %d entries", MaxClientErrorContext)
	}
	for k, v := range r.Context {
		if k == "" || len(k) > MaxClientErrorContextKey {
			return invalid("context keys must be 1 to %d bytes", MaxClientErrorContextKey)
		}
		if len(v) > MaxClientErrorContextValue {
			return invalid("context values must be at most %d bytes", MaxClientErrorContextValue)
		}
	}
	return nil
}

// allow counts a report against the user's fixed window and reports whether it is
// within the limit.
func (c *ClientErrors) allow(userID uuid.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// Forget windows that have ended, so the map holds only recent reporters.
	for id, w := range c.windows {
		if now.Sub(w.start) >= c.window {
			delete(c.windows, id)
		}
	}
	w, ok := c.windows[userID]
	if !ok {
		w = &reportWindow{start: now}
		c.windows[userID] = w
	}
	if w.count >= c.limit {
		return false
	}
	w.count++
	return true
}
