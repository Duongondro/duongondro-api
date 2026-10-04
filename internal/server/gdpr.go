package server

import (
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/store"
)

// exportMe answers GDPR Art. 15 and 20: everything held about the caller,
// one key per table that references a user.
func (s *Server) exportMe(w http.ResponseWriter, r *http.Request) {
	a := caller(r)
	tables, err := s.store.Export(r.Context(), a.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		UserID     string                      `json:"userId"`
		ExportedAt int64                       `json:"exportedAt"`
		Tables     map[string][]map[string]any `json:"tables"`
	}{a.UserID, s.now().UnixMilli(), tables})
}

// deleteMe answers GDPR Art. 17: one transaction removes every row of the
// caller, then the Sign in with Apple token is revoked. It returns only when
// both are done.
func (s *Server) deleteMe(w http.ResponseWriter, r *http.Request) {
	a := caller(r)
	subjects, err := s.store.Purge(r.Context(), a.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, sub := range subjects {
		if err := s.revoker.Revoke(r.Context(), sub); err != nil {
			// The account is gone either way; the token expires on Apple's side.
			s.log.Warn("sign in with apple revocation failed", "err", err)
		}
	}
	s.log.Info("account purged")
	w.WriteHeader(http.StatusNoContent)
}
