package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

// maxClockSkew: a phone with a clock far ahead would otherwise protect a
// log against every later edit (CodeShare's rule).
const maxClockSkew = 24 * time.Hour

// validSealedSize: nonce(12) ‖ ciphertext ‖ tag(16) of JSON padded to a
// multiple of 256 bytes, at most 16 KiB.
func validSealedSize(n int) bool { return n >= 28+256 && n <= 16384 && (n-28)%256 == 0 }

type practiceLogJSON struct {
	ID         string     `json:"id"`
	Sealed     e2ee.Bytes `json:"sealed"`
	KeyVersion int32      `json:"keyVersion"`
	UpdatedAt  int64      `json:"updatedAt"`
	Deleted    bool       `json:"deleted"`
}

func logOut(l store.PracticeLog) practiceLogJSON {
	return practiceLogJSON{ID: l.ID, Sealed: l.Sealed, KeyVersion: l.KeyVersion, UpdatedAt: l.UpdatedAt.UnixMilli(), Deleted: l.Deleted}
}

func (s *Server) putPracticeLog(w http.ResponseWriter, r *http.Request) {
	u, err := ids.ParseUUID(r.PathValue("logId"))
	var req struct {
		Sealed     e2ee.Bytes `json:"sealed"`
		KeyVersion int32      `json:"keyVersion"`
		UpdatedAt  int64      `json:"updatedAt"`
		Deleted    bool       `json:"deleted"`
	}
	if err != nil || !u.IsV7() {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !decode(w, r, &req) {
		return
	}
	if !validSealedSize(len(req.Sealed)) || req.KeyVersion < 1 || req.UpdatedAt <= 0 ||
		time.UnixMilli(req.UpdatedAt).After(s.now().Add(maxClockSkew)) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	out, current, err := s.store.PutPracticeLog(r.Context(), store.PracticeLog{
		ID: u.String(), UserID: a.UserID, Sealed: req.Sealed, KeyVersion: req.KeyVersion,
		UpdatedAt: time.UnixMilli(req.UpdatedAt), Deleted: req.Deleted,
	})
	switch {
	case errors.Is(err, store.ErrKeyVersion):
		writeJSON(w, http.StatusUnprocessableEntity, keyVersionError{Error: "old_key_version", CurrentKeyVersion: current})
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, http.StatusOK, logOut(out))
	}
}

func (s *Server) sync(w http.ResponseWriter, r *http.Request) {
	var since *store.Cursor
	if v := r.URL.Query().Get("since"); v != "" {
		c, err := store.ParseCursor(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		since = &c
	}
	res, err := s.store.Sync(r.Context(), caller(r).UserID, since)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	logs := make([]practiceLogJSON, 0, len(res.Logs))
	for _, l := range res.Logs {
		logs = append(logs, logOut(l))
	}
	writeJSON(w, http.StatusOK, struct {
		Cursor     string            `json:"cursor"`
		Full       bool              `json:"full"`
		KeyVersion int32             `json:"keyVersion"`
		Logs       []practiceLogJSON `json:"logs"`
	}{res.Cursor.String(), res.Full, res.KeyVersion, logs})
}
