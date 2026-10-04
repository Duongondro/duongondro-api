//go:build DEV

package server

import (
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

// devEnabled reports whether this binary has the dev session route.
const devEnabled = true

// registerDev adds POST /api/dev/session, which signs in without mail or an
// invite, for the Simulator. It renders the server trivially insecure, so it
// exists only in binaries built with -tags DEV; leaving the tag out removes
// it (CodeShare's fail-safe direction).
func registerDev(s *Server, mux *http.ServeMux) {
	mux.HandleFunc("POST /api/dev/session", s.devSession)
}

func (s *Server) devSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string     `json:"userId"`
		DisplayName string     `json:"displayName"`
		IdentityPK  e2ee.Bytes `json:"identityPk"`
	}
	if !decode(w, r, &req) {
		return
	}
	id := ids.NewV7().String()
	if req.UserID != "" {
		u, err := ids.ParseUUID(req.UserID)
		if err != nil || !u.IsV7() {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		id = u.String()
	}
	if req.DisplayName == "" {
		req.DisplayName = "Dev"
	}
	if !validName(req.DisplayName) || (req.IdentityPK != nil && len(req.IdentityPK) != 32) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	err := s.store.CreateUser(r.Context(), id, req.DisplayName, req.IdentityPK)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		s.fail(w, r, err)
		return
	}
	tok, hash := ids.NewToken()
	if err := s.store.CreateSession(r.Context(), hash, id); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionJSON{Token: tok, UserID: id})
}
