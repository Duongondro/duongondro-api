package server

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

const (
	magicLinkTTL = 15 * time.Minute
	signupTTL    = time.Hour
)

type ctxKey struct{}

// auth is the authenticated caller.
type auth struct {
	UserID    string
	DeviceID  string // empty until this session registers a device
	tokenHash []byte
}

func caller(r *http.Request) *auth { return r.Context().Value(ctxKey{}).(*auth) }

// bearer extracts the token from Authorization, or "".
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	tok := strings.TrimSpace(h[7:])
	if len(tok) != 43 { // 32 bytes, unpadded base64url
		return ""
	}
	return tok
}

// authenticate resolves the bearer token. ok is false with the response
// already written.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*auth, bool) {
	tok := bearer(r)
	if tok == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return nil, false
	}
	h := ids.HashToken(tok)
	sess, err := s.store.SessionByHash(r.Context(), h)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return nil, false
	}
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	return &auth{UserID: sess.UserID, DeviceID: sess.DeviceID, tokenHash: h}, true
}

// authed wraps a handler that needs a session.
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)))
	}
}

// normaliseEmail lowercases and trims; ok is false for anything that is not
// a bare address.
func normaliseEmail(s string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(s))
	if len(e) < 3 || len(e) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" || !strings.Contains(e[strings.LastIndexByte(e, '@')+1:], ".") {
		return "", false
	}
	return e, true
}

func (s *Server) requestMagicLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	email, ok := normaliseEmail(req.Email)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !s.limits.authIP.allow(clientIP(r)) || !s.limits.mailAddress.allow(email) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	// A link is sent whether or not an account exists, and the answer is
	// the same either way: the route cannot enumerate members.
	tok, hash := ids.NewToken()
	if err := s.store.CreateMagicLink(r.Context(), hash, email, s.now().Add(magicLinkTTL)); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.mail.SendMagicLink(r.Context(), email, s.linkBase+tok); err != nil {
		s.log.Warn("magic link not sent", "err", err)
	}
	w.WriteHeader(http.StatusAccepted)
}

type sessionJSON struct {
	Token  string `json:"token"`
	UserID string `json:"userId"`
}

func (s *Server) verifyMagicLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Token == "" || len(req.Token) > 64 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !s.limits.authIP.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	email, err := s.store.ConsumeMagicLink(r.Context(), ids.HashToken(req.Token))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type result struct {
		Status      string       `json:"status"`
		Session     *sessionJSON `json:"session,omitempty"`
		SignupToken string       `json:"signupToken,omitempty"`
	}
	userID, err := s.store.UserByEmail(r.Context(), email)
	switch {
	case err == nil:
		// Signing in never grants keys: the session can register a device,
		// but only a device in the signed device list receives wraps.
		tok, hash := ids.NewToken()
		if err := s.store.CreateSession(r.Context(), hash, userID); err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, result{Status: "signed_in", Session: &sessionJSON{Token: tok, UserID: userID}})
	case errors.Is(err, store.ErrNotFound):
		tok, hash := ids.NewToken()
		if err := s.store.CreateSignupToken(r.Context(), hash, email, s.now().Add(signupTTL)); err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, result{Status: "signup_required", SignupToken: tok})
	default:
		s.fail(w, r, err)
	}
}

func (s *Server) signOut(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSession(r.Context(), caller(r).tokenHash); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type accountJSON struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName"`
	AvatarRef   *string    `json:"avatarRef"`
	IdentityPK  e2ee.Bytes `json:"identityPk"`
	KeyVersion  int32      `json:"keyVersion"`
	CreatedAt   int64      `json:"createdAt"`
}

func account(u store.User) accountJSON {
	return accountJSON{
		ID:          u.ID,
		DisplayName: u.DisplayName,
		AvatarRef:   u.AvatarRef,
		IdentityPK:  nullBytes(u.IdentityPK),
		KeyVersion:  u.KeyVersion,
		CreatedAt:   u.CreatedAt.UnixMilli(),
	}
}

// nullBytes makes an empty byte string marshal as null.
func nullBytes(b []byte) e2ee.Bytes {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (s *Server) getMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUser(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, account(u))
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName optional[string] `json:"displayName"`
		AvatarRef   optional[string] `json:"avatarRef"`
	}
	if !decode(w, r, &req) {
		return
	}
	var up store.UserUpdate
	if req.DisplayName.Set {
		if req.DisplayName.Value == nil || !validName(*req.DisplayName.Value) {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		up.DisplayName = req.DisplayName.Value
	}
	if req.AvatarRef.Set {
		if v := req.AvatarRef.Value; v != nil && (len(*v) == 0 || len(*v) > 128 || !validName(*v)) {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		up.SetAvatar, up.AvatarRef = true, req.AvatarRef.Value
	}
	u, err := s.store.UpdateUser(r.Context(), caller(r).UserID, up)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, account(u))
}
