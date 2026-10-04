//go:build DEV

package server

import (
	"net/http"
	"testing"
)

func TestDevSession(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", "/api/dev/session", "", map[string]string{"displayName": "Sim"})
	e.want(r, http.StatusOK, "")
	var s sessionJSON
	r.json(t, &s)
	e.want(e.call("GET", "/api/me", s.Token, nil), http.StatusOK, "")
}
