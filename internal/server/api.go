package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// apiError is the Error schema; extra fields come from the embedding types.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type keyVersionError struct {
	Error             string `json:"error"`
	CurrentKeyVersion int32  `json:"currentKeyVersion"`
}

type versionError struct {
	Error          string `json:"error"`
	CurrentVersion int64  `json:"currentVersion"`
}

var messages = map[string]string{
	"bad_request":        "Malformed body or parameter.",
	"unauthorized":       "Missing or invalid bearer token.",
	"not_found":          "Not found.",
	"method_not_allowed": "Method not allowed for this path.",
	"rate_limited":       "Too many requests.",
	"too_large":          "Request body over 64 KiB.",
	"internal":           "Internal error.",
	"invalid_token":      "Unknown, expired or already used token.",
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, apiError{Error: code, Message: messages[code]})
}

// fail answers 500 and logs the cause. ERROR is reserved for 5xx.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "method", r.Method, "path", r.Pattern, "err", err)
	writeError(w, http.StatusInternalServerError, "internal")
}

// decode reads exactly one JSON object into v, refusing unknown fields. It
// writes the error response itself and reports whether to continue.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, extra := dec.Token(); extra != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request")
		}
		return false
	}
	return true
}

// validName accepts 1–64 characters of printable text without leading or
// trailing space: display names are shown to friends.
func validName(s string) bool {
	if !utf8.ValidString(s) || s != strings.TrimSpace(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n < 1 || n > 64 {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) && r != ' ' {
			return false
		}
	}
	return true
}

// optional distinguishes an absent JSON key from an explicit null.
type optional[T any] struct {
	Set   bool
	Value *T
}

func (o *optional[T]) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}
