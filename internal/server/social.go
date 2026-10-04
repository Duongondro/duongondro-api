package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/push"
	"github.com/Duongondro/duongondro-api/internal/store"
)

const (
	maxStatementBytes = 1024
	maxInviteLifetime = 30 * 24 * time.Hour
)

var practiceKey = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ---- Invites ----

type inviteSummaryJSON struct {
	InviteID    string `json:"inviteId"`
	ExpiresAt   int64  `json:"expiresAt"`
	CreatedAt   int64  `json:"createdAt"`
	RevokedAt   *int64 `json:"revokedAt"`
	Redemptions int    `json:"redemptions"`
}

func inviteSummary(inv store.Invite) inviteSummaryJSON {
	var revoked *int64
	if inv.RevokedAt != nil {
		v := inv.RevokedAt.UnixMilli()
		revoked = &v
	}
	return inviteSummaryJSON{InviteID: inv.ID, ExpiresAt: inv.ExpiresAt.UnixMilli(), CreatedAt: inv.CreatedAt.UnixMilli(), RevokedAt: revoked, Redemptions: inv.Redemptions}
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Payload   e2ee.Bytes `json:"payload"`
		Signature e2ee.Bytes `json:"signature"`
		MAC       e2ee.Bytes `json:"mac"`
		AuthKey   e2ee.Bytes `json:"authKey"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Payload) < 2 || len(req.Payload) > maxStatementBytes || !validSignature(req.Signature) || len(req.MAC) != 32 || len(req.AuthKey) != 32 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	if !s.limits.inviteMake.allow(a.UserID) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	identity, ok := s.identityOf(w, r, a.UserID)
	if !ok {
		return
	}
	if !e2ee.VerifyStatement(identity, e2ee.TypeInvite, req.Payload, req.Signature) {
		s.unprocessable(w, "bad_signature", "The signature does not verify with the pinned identity key.")
		return
	}
	var inv e2ee.Invite
	if err := strictUnmarshal(req.Payload, &inv); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	id, ok := ids.InviteID(inv.InviteID)
	expires := time.UnixMilli(inv.ExpiresAt)
	now := s.now()
	if !ok || id != inv.InviteID || !expires.After(now) || expires.After(now.Add(maxInviteLifetime)) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !sameUser(inv.Inviter, a.UserID) || !bytes.Equal(inv.InviterIdentityPk, identity) {
		s.unprocessable(w, "wrong_user", "The record names another inviter or key.")
		return
	}
	hash := sha256Sum(req.AuthKey)
	err := s.store.CreateInvite(r.Context(), store.Invite{
		ID: id, InviterID: a.UserID, AuthKeyHash: hash, Payload: req.Payload, Signature: req.Signature, MAC: req.MAC, ExpiresAt: expires,
	})
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, apiError{Error: "invite_exists", Message: "An invite with this id exists."})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	stored, err := s.store.GetInvite(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, inviteSummary(stored))
}

func (s *Server) listInvites(w http.ResponseWriter, r *http.Request) {
	invs, err := s.store.ListInvites(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]inviteSummaryJSON, 0, len(invs))
	for _, inv := range invs {
		out = append(out, inviteSummary(inv))
	}
	writeJSON(w, http.StatusOK, out)
}

// pathInvite normalises the invite id path value.
func pathInvite(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := ids.InviteID(r.PathValue("inviteId"))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
	}
	return id, ok
}

func gone(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusGone, apiError{Error: code, Message: "This invite can no longer be used."})
}

func (s *Server) getInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInvite(w, r)
	if !ok {
		return
	}
	if !s.limits.inviteIP.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	inv, err := s.store.GetInvite(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	case inv.RevokedAt != nil:
		gone(w, "invite_revoked")
		return
	case !inv.ExpiresAt.After(s.now()):
		gone(w, "invite_expired")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		InviteID           string     `json:"inviteId"`
		Payload            e2ee.Bytes `json:"payload"`
		Signature          e2ee.Bytes `json:"signature"`
		MAC                e2ee.Bytes `json:"mac"`
		InviterDisplayName string     `json:"inviterDisplayName"`
	}{inv.ID, inv.Payload, inv.Signature, inv.MAC, inv.InviterName})
}

func (s *Server) revokeInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInvite(w, r)
	if !ok {
		return
	}
	err := s.store.RevokeInvite(r.Context(), caller(r).UserID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRedemptions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInvite(w, r)
	if !ok {
		return
	}
	rs, err := s.store.ListRedemptions(r.Context(), caller(r).UserID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type redemptionJSON struct {
		Invitee    string      `json:"invitee"`
		RedeemedAt int64       `json:"redeemedAt"`
		Acceptance *signedJSON `json:"acceptance"`
	}
	out := make([]redemptionJSON, 0, len(rs))
	for _, x := range rs {
		var acc *signedJSON
		if x.AcceptancePayload != nil {
			acc = &signedJSON{Payload: x.AcceptancePayload, Signature: x.AcceptanceSignature}
		}
		out = append(out, redemptionJSON{Invitee: x.InviteeID, RedeemedAt: x.RedeemedAt.UnixMilli(), Acceptance: acc})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) redeemInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInvite(w, r)
	if !ok {
		return
	}
	var req struct {
		AuthKey    e2ee.Bytes `json:"authKey"`
		Acceptance signedJSON `json:"acceptance"`
		Signup     *struct {
			SignupToken string `json:"signupToken"`
			UserID      string `json:"userId"`
			DisplayName string `json:"displayName"`
		} `json:"signup"`
	}
	if !decode(w, r, &req) {
		return
	}
	acc := req.Acceptance
	if len(req.AuthKey) != 32 || len(acc.Payload) < 2 || len(acc.Payload) > maxStatementBytes || !validSignature(acc.Signature) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !s.limits.inviteIP.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	signedIn := r.Header.Get("Authorization") != ""
	if signedIn == (req.Signup != nil) {
		// Exactly one of a bearer token and a sign-up.
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}

	var invitee string
	var identity ed25519.PublicKey
	var parsed e2ee.Acceptance
	if signedIn {
		a, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		invitee = a.UserID
		if identity, ok = s.identityOf(w, r, invitee); !ok {
			return
		}
		// Verify over the exact bytes, then parse.
		if !e2ee.VerifyStatement(identity, e2ee.TypeAcceptance, acc.Payload, acc.Signature) {
			s.unprocessable(w, "bad_signature", "The acceptance does not verify with the pinned identity key.")
			return
		}
		if err := strictUnmarshal(acc.Payload, &parsed); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
	} else {
		u, err := ids.ParseUUID(req.Signup.UserID)
		if err != nil || !u.IsV7() || !validName(req.Signup.DisplayName) || req.Signup.SignupToken == "" || len(req.Signup.SignupToken) > 64 {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		invitee = u.String()
		// A new account has no pinned key yet: the acceptance carries it,
		// and must verify under it, before it is pinned.
		if err := strictUnmarshal(acc.Payload, &parsed); err != nil || len(parsed.InviteeIdentityPk) != ed25519.PublicKeySize {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		identity = ed25519.PublicKey(parsed.InviteeIdentityPk)
		if !e2ee.VerifyStatement(identity, e2ee.TypeAcceptance, acc.Payload, acc.Signature) {
			s.unprocessable(w, "bad_signature", "The acceptance does not verify with the key it carries.")
			return
		}
	}
	if parsed.InviteID != id || !sameUser(parsed.Invitee, invitee) || !bytes.Equal(parsed.InviteeIdentityPk, identity) {
		s.unprocessable(w, "wrong_user", "The acceptance names another invite, invitee or key.")
		return
	}

	stored := store.Acceptance{Payload: acc.Payload, Signature: acc.Signature}
	var inviter string
	var err error
	var session *sessionJSON
	if signedIn {
		inviter, err = s.store.RedeemInvite(r.Context(), s.now(), id, invitee, req.AuthKey, stored)
	} else {
		tok, hash := ids.NewToken()
		inviter, err = s.store.RedeemInviteSignup(r.Context(), s.now(), id, req.AuthKey, stored, store.NewAccount{
			UserID: invitee, DisplayName: req.Signup.DisplayName, IdentityPK: identity,
			SignupHash: ids.HashToken(req.Signup.SignupToken), SessionHash: hash,
		})
		session = &sessionJSON{Token: tok, UserID: invitee}
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, store.ErrBadAuthKey):
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "bad_auth_key", Message: "Wrong invite auth key."})
	case errors.Is(err, store.ErrInvalidToken):
		writeError(w, http.StatusUnauthorized, "invalid_token")
	case errors.Is(err, store.ErrInviteRevoked):
		gone(w, "invite_revoked")
	case errors.Is(err, store.ErrInviteExpired):
		gone(w, "invite_expired")
	case errors.Is(err, store.ErrOwnInvite):
		writeJSON(w, http.StatusForbidden, apiError{Error: "own_invite", Message: "This is your own invite."})
	case errors.Is(err, store.ErrBlocked):
		writeJSON(w, http.StatusForbidden, apiError{Error: "blocked", Message: "Blocked."})
	case errors.Is(err, store.ErrUserExists):
		writeJSON(w, http.StatusConflict, apiError{Error: "user_exists", Message: "The user id or the email already has an account."})
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, http.StatusOK, struct {
			UserID  string       `json:"userId"`
			Inviter string       `json:"inviter"`
			Session *sessionJSON `json:"session,omitempty"`
		}{invitee, inviter, session})
	}
}

// ---- Friends ----

func (s *Server) listFriends(w http.ResponseWriter, r *http.Request) {
	fs, err := s.store.ListFriends(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type friendJSON struct {
		UserID      string     `json:"userId"`
		DisplayName string     `json:"displayName"`
		AvatarRef   *string    `json:"avatarRef"`
		IdentityPK  e2ee.Bytes `json:"identityPk"`
		Since       int64      `json:"since"`
		Blocked     bool       `json:"blocked"`
	}
	out := make([]friendJSON, 0, len(fs))
	for _, f := range fs {
		out = append(out, friendJSON{f.UserID, f.DisplayName, f.AvatarRef, nullBytes(f.IdentityPK), f.Since.UnixMilli(), f.Blocked})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) unfriend(w http.ResponseWriter, r *http.Request) {
	other, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	err := s.store.Unfriend(r.Context(), caller(r).UserID, other)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Streaks ----

type streakJSON struct {
	User      string     `json:"user"`
	Practice  string     `json:"practice"`
	Seq       int64      `json:"seq"`
	Payload   e2ee.Bytes `json:"payload"`
	Signature e2ee.Bytes `json:"signature"`
}

func streakOut(st store.StreakStatement) streakJSON {
	return streakJSON{User: st.UserID, Practice: st.Practice, Seq: st.Seq, Payload: st.Payload, Signature: st.Signature}
}

func (s *Server) publishStreak(w http.ResponseWriter, r *http.Request) {
	var req signedJSON
	if !decode(w, r, &req) {
		return
	}
	if len(req.Payload) < 2 || len(req.Payload) > maxStatementBytes || !validSignature(req.Signature) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	identity, ok := s.identityOf(w, r, a.UserID)
	if !ok {
		return
	}
	if !e2ee.VerifyStatement(identity, e2ee.TypeStreak, req.Payload, req.Signature) {
		s.unprocessable(w, "bad_signature", "The signature does not verify with the pinned identity key.")
		return
	}
	var st e2ee.Streak
	if err := strictUnmarshal(req.Payload, &st); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	day, err := time.Parse("2006-01-02", st.Day)
	if err != nil || day.Format("2006-01-02") != st.Day || !practiceKey.MatchString(st.Practice) ||
		st.Current < 0 || st.Longest < st.Current || st.Longest > 1<<30 || st.Seq < 0 || st.Deadline <= 0 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !sameUser(st.User, a.UserID) {
		s.unprocessable(w, "wrong_user", "The payload names another user.")
		return
	}
	stored := store.StreakStatement{
		UserID: a.UserID, Practice: st.Practice, Seq: st.Seq, Day: day,
		Current: int32(st.Current), Longest: int32(st.Longest), Deadline: time.UnixMilli(st.Deadline),
		Payload: req.Payload, Signature: req.Signature,
	}
	newDay, current, err := s.store.PublishStreak(r.Context(), stored)
	if errors.Is(err, store.ErrStale) {
		writeJSON(w, http.StatusConflict, versionError{Error: "stale_seq", CurrentVersion: current})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if newDay && st.Current > 0 {
		s.notifyFriends(r.Context(), a.UserID, func(name string) push.Notification {
			return push.DoneToday(name, st.Practice, st.Current, st.Day)
		})
	}
	writeJSON(w, http.StatusOK, streakOut(stored))
}

// notifyFriends pushes to every friend of userID with no block either way.
// Failures are logged, never returned: the statement is already stored.
func (s *Server) notifyFriends(ctx context.Context, userID string, build func(name string) push.Notification) {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		s.log.Warn("push: load sender", "user", userID, "err", err)
		return
	}
	friends, err := s.store.ConnectedFriends(ctx, userID)
	if err != nil {
		s.log.Warn("push: load friends", "user", userID, "err", err)
		return
	}
	s.pushTo(ctx, friends, build(u.DisplayName))
}

func (s *Server) pushTo(ctx context.Context, users []string, n push.Notification) {
	tokens, err := s.store.PushTokens(ctx, users)
	if err != nil {
		s.log.Warn("push: load tokens", "err", err)
		return
	}
	if len(tokens) == 0 {
		return
	}
	out := make([]push.Token, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, push.Token{DeviceID: t.DeviceID, Platform: t.Platform, Token: t.Token})
	}
	if err := s.push.Send(ctx, out, n); err != nil {
		s.log.Warn("push: send", "kind", n.Kind, "err", err)
	}
}

func (s *Server) unpublishStreak(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("practice")
	if !practiceKey.MatchString(p) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := s.store.UnpublishStreak(r.Context(), caller(r).UserID, p); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) friendStreaks(w http.ResponseWriter, r *http.Request) {
	sts, err := s.store.FriendStreaks(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]streakJSON, 0, len(sts))
	for _, st := range sts {
		out = append(out, streakOut(st))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- Blocks and reports ----

// otherUser parses the userId path value and checks it names a real
// account other than the caller.
func (s *Server) otherUser(w http.ResponseWriter, r *http.Request, id string) bool {
	if id == caller(r).UserID {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	ok, err := s.store.UserExists(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
	}
	return ok
}

func (s *Server) block(w http.ResponseWriter, r *http.Request) {
	other, ok := pathUUID(w, r, "userId")
	if !ok || !s.otherUser(w, r, other) {
		return
	}
	if err := s.store.BlockUser(r.Context(), caller(r).UserID, other); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unblock(w http.ResponseWriter, r *http.Request) {
	other, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	if err := s.store.UnblockUser(r.Context(), caller(r).UserID, other); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listBlocks(w http.ResponseWriter, r *http.Request) {
	bs, err := s.store.ListBlocks(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type blockJSON struct {
		UserID    string `json:"userId"`
		CreatedAt int64  `json:"createdAt"`
	}
	out := make([]blockJSON, 0, len(bs))
	for _, b := range bs {
		out = append(out, blockJSON{b.UserID, b.CreatedAt.UnixMilli()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string  `json:"userId"`
		Reason string  `json:"reason"`
		Note   *string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	other, ok := ids.CanonicalUUID(req.UserID)
	switch req.Reason {
	case "name", "avatar", "spam", "other":
	default:
		ok = false
	}
	if req.Note != nil && len([]rune(*req.Note)) > 1000 {
		ok = false
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	if !s.otherUser(w, r, other) {
		return
	}
	if !s.limits.reports.allow(a.UserID) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if err := s.store.Report(r.Context(), a.UserID, other, req.Reason, req.Note); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// ---- Push ----

func (s *Server) putPushToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Platform string `json:"platform"`
		Token    string `json:"token"`
	}
	if !decode(w, r, &req) {
		return
	}
	if (req.Platform != "apns" && req.Platform != "fcm") || len(req.Token) == 0 || len(req.Token) > 4096 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	if a.DeviceID == "" {
		writeJSON(w, http.StatusConflict, apiError{Error: "no_device", Message: "Register this device first."})
		return
	}
	if err := s.store.PutPushToken(r.Context(), store.PushToken{DeviceID: a.DeviceID, UserID: a.UserID, Platform: req.Platform, Token: req.Token}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deletePushToken(w http.ResponseWriter, r *http.Request) {
	a := caller(r)
	if a.DeviceID != "" {
		if err := s.store.DeletePushToken(r.Context(), a.UserID, a.DeviceID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) poke(w http.ResponseWriter, r *http.Request) {
	friend, ok := pathUUID(w, r, "friendId")
	if !ok {
		return
	}
	a := caller(r)
	// A block either way looks like a stranger.
	connected, err := s.store.Connected(r.Context(), a.UserID, friend)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !connected {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	err = s.store.Poke(r.Context(), a.UserID, friend, s.now())
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "already_poked", Message: "One poke per friend per day."})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	me, err := s.store.GetUser(r.Context(), a.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.pushTo(r.Context(), []string{friend}, push.Poke(me.DisplayName, a.UserID))
	w.WriteHeader(http.StatusNoContent)
}
