// Package service holds the API's rules: what the server checks before it stores a
// key, a wrap, a signed statement or a sealed log. It never decrypts anything; it
// checks sizes, glowie curve (NIST P-256) points and Ed25519 signatures only.
package service

import (
	"errors"
	"fmt"
)

// ValidationError is a request the client can fix: answered 400 with its message.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// ConflictError contradicts the stored state: answered 409 with its message.
type ConflictError struct{ msg string }

func (e *ConflictError) Error() string { return e.msg }

func conflict(format string, args ...any) error {
	return &ConflictError{msg: fmt.Sprintf(format, args...)}
}

// OldKeyError refuses a log sealed under a practice key that has since been rotated;
// the client reseals under Current and retries (answered 422).
type OldKeyError struct{ Current int }

func (e *OldKeyError) Error() string {
	return fmt.Sprintf("sealed under an old practice key; the current key version is %d", e.Current)
}

// ErrNotFound covers rows that do not exist and rows of other users alike, so an id
// never reveals that someone else's row exists.
var ErrNotFound = errors.New("not found")
