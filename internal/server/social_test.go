package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/push"
)

type testInvite struct {
	ID      string
	Body    map[string]any
	AuthKey []byte
	Pin     []byte
}

func makeInvite(t *testing.T, inviter *user, expiresAt time.Time) testInvite {
	t.Helper()
	secret := make([]byte, 10)
	_, _ = rand.Read(secret)
	auth, pin := e2ee.InviteKeys(secret)
	pk := inviter.Identity.Public().(ed25519.PublicKey)
	id := ids.NewInviteID()
	payload, err := e2ee.Marshal(e2ee.Invite{ExpiresAt: expiresAt.UnixMilli(), InviteID: id, Inviter: inviter.ID, InviterIdentityPk: e2ee.Bytes(pk)})
	if err != nil {
		t.Fatal(err)
	}
	return testInvite{
		ID: id, AuthKey: auth, Pin: pin,
		Body: map[string]any{
			"payload":   e2ee.Bytes(payload),
			"signature": e2ee.Bytes(e2ee.SignStatement(inviter.Identity, e2ee.TypeInvite, payload)),
			"mac":       e2ee.Bytes(e2ee.InviteMAC(pin, pk)),
			"authKey":   e2ee.Bytes(auth),
		},
	}
}

func acceptance(t *testing.T, inviteID, invitee string, identity ed25519.PrivateKey) map[string]any {
	t.Helper()
	payload, err := e2ee.Marshal(e2ee.Acceptance{InviteID: inviteID, Invitee: invitee, InviteeIdentityPk: e2ee.Bytes(identity.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"payload": e2ee.Bytes(payload), "signature": e2ee.Bytes(e2ee.SignStatement(identity, e2ee.TypeAcceptance, payload))}
}

// signupToken runs the magic-link flow for an address without an account.
func (e *env) signupToken(email string) string {
	e.t.Helper()
	e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": email}), http.StatusAccepted, "")
	tok := strings.TrimPrefix(e.mail.last(email), "https://duongondro.app/m#")
	r := e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": tok})
	e.want(r, http.StatusOK, "")
	var res struct {
		SignupToken string `json:"signupToken"`
	}
	r.json(e.t, &res)
	return res.SignupToken
}

func newIdentity() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

type redeemResult struct {
	UserID  string       `json:"userId"`
	Inviter string       `json:"inviter"`
	Session *sessionJSON `json:"session"`
}

func TestInviteSignup(t *testing.T) {
	e := newEnv(t)
	inviter := e.newUser("Tenzin")
	inv := makeInvite(t, inviter, e.clock().Add(7*24*time.Hour))
	r := e.call("POST", "/api/invites", inviter.Token, inv.Body)
	e.want(r, http.StatusCreated, "")
	var sum inviteSummaryJSON
	r.json(t, &sum)
	if sum.InviteID != inv.ID || sum.Redemptions != 0 || sum.RevokedAt != nil {
		t.Fatalf("summary %s", r.Body)
	}

	// The invitee's phone fetches the record without signing in, checks the
	// signature and the MAC with the pin from the link.
	r = e.call("GET", "/api/invites/"+strings.ToLower(inv.ID), "", nil)
	e.want(r, http.StatusOK, "")
	var rec struct {
		Payload            e2ee.Bytes `json:"payload"`
		Signature          e2ee.Bytes `json:"signature"`
		MAC                e2ee.Bytes `json:"mac"`
		InviterDisplayName string     `json:"inviterDisplayName"`
	}
	r.json(t, &rec)
	pk := inviter.Identity.Public().(ed25519.PublicKey)
	if !e2ee.VerifyStatement(pk, e2ee.TypeInvite, rec.Payload, rec.Signature) || !e2ee.EqualTag(rec.MAC, e2ee.InviteMAC(inv.Pin, pk)) || rec.InviterDisplayName != "Tenzin" {
		t.Fatalf("record %s", r.Body)
	}

	// Two newcomers redeem the same reusable invite.
	for i, email := range []string{"dolma@example.org", "karma@example.org"} {
		signup := e.signupToken(email)
		identity := newIdentity()
		uid := ids.NewV7().String()
		r = e.call("POST", "/api/invites/"+inv.ID+"/redeem", "", map[string]any{
			"authKey":    e2ee.Bytes(inv.AuthKey),
			"acceptance": acceptance(t, inv.ID, uid, identity),
			"signup":     map[string]any{"signupToken": signup, "userId": uid, "displayName": "Newcomer"},
		})
		e.want(r, http.StatusOK, "")
		var res redeemResult
		r.json(t, &res)
		if res.UserID != uid || res.Inviter != inviter.ID || res.Session == nil {
			t.Fatalf("redeem %d: %s", i, r.Body)
		}
		// The identity key is pinned from the acceptance; the friendship exists.
		var me accountJSON
		e.call("GET", "/api/me", res.Session.Token, nil).json(t, &me)
		if string(me.IdentityPK) != string(identity.Public().(ed25519.PublicKey)) {
			t.Fatal("identity not pinned")
		}
		var friends []struct {
			UserID     string     `json:"userId"`
			IdentityPK e2ee.Bytes `json:"identityPk"`
		}
		e.call("GET", "/api/friends", res.Session.Token, nil).json(t, &friends)
		if len(friends) != 1 || friends[0].UserID != inviter.ID || string(friends[0].IdentityPK) != string(pk) {
			t.Fatalf("friends %v", friends)
		}
		// The address now signs in.
		e.want(e.call("POST", "/api/auth/magic-link", "", map[string]string{"email": email}), http.StatusAccepted, "")
		tok := strings.TrimPrefix(e.mail.last(email), "https://duongondro.app/m#")
		var sr struct {
			Status string `json:"status"`
		}
		e.call("POST", "/api/auth/magic-link/verify", "", map[string]string{"token": tok}).json(t, &sr)
		if sr.Status != "signed_in" {
			t.Fatalf("sign-in after sign-up: %s", sr.Status)
		}
	}

	var redemptions []struct {
		Invitee    string     `json:"invitee"`
		Acceptance signedJSON `json:"acceptance"`
	}
	r = e.call("GET", "/api/invites/"+inv.ID+"/redemptions", inviter.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &redemptions)
	if len(redemptions) != 2 || len(redemptions[0].Acceptance.Signature) != 64 {
		t.Fatalf("redemptions %s", r.Body)
	}
	var friends []any
	e.call("GET", "/api/friends", inviter.Token, nil).json(t, &friends)
	if len(friends) != 2 {
		t.Fatalf("inviter friends %v", friends)
	}
	var list []inviteSummaryJSON
	e.call("GET", "/api/invites", inviter.Token, nil).json(t, &list)
	if len(list) != 1 || list[0].Redemptions != 2 {
		t.Fatalf("invites %v", list)
	}
}

func TestInviteRules(t *testing.T) {
	e := newEnv(t)
	inviter := e.newUser("Tenzin")
	week := e.clock().Add(7 * 24 * time.Hour)

	// Creation checks.
	inv := makeInvite(t, inviter, week)
	forged := makeInvite(t, e.newUser("Mallory"), week)
	e.want(e.call("POST", "/api/invites", inviter.Token, forged.Body), http.StatusUnprocessableEntity, "bad_signature")
	e.want(e.call("POST", "/api/invites", inviter.Token, makeInvite(t, inviter, e.clock().Add(31*24*time.Hour)).Body), http.StatusBadRequest, "bad_request")
	e.want(e.call("POST", "/api/invites", inviter.Token, makeInvite(t, inviter, e.clock().Add(-time.Minute)).Body), http.StatusBadRequest, "bad_request")
	other := e.newUser("Other")
	stolen := makeInvite(t, &user{ID: other.ID, Identity: inviter.Identity}, week)
	e.want(e.call("POST", "/api/invites", inviter.Token, stolen.Body), http.StatusUnprocessableEntity, "wrong_user")
	e.want(e.call("POST", "/api/invites", inviter.Token, inv.Body), http.StatusCreated, "")
	e.want(e.call("POST", "/api/invites", inviter.Token, inv.Body), http.StatusConflict, "invite_exists")
	e.want(e.call("GET", "/api/invites/ZZZZZZZZ", "", nil), http.StatusNotFound, "not_found")
	e.want(e.call("GET", "/api/invites/bad", "", nil), http.StatusBadRequest, "bad_request")

	// A signed-in member redeems: idempotent, and acceptances are checked.
	member := e.newUser("Dolma")
	body := map[string]any{"authKey": e2ee.Bytes(inv.AuthKey), "acceptance": acceptance(t, inv.ID, member.ID, member.Identity)}
	r := e.call("POST", "/api/invites/"+inv.ID+"/redeem", member.Token, body)
	e.want(r, http.StatusOK, "")
	var res redeemResult
	r.json(t, &res)
	if res.Session != nil || res.Inviter != inviter.ID {
		t.Fatalf("redeem %s", r.Body)
	}
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", member.Token, body), http.StatusOK, "")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", member.Token, map[string]any{"authKey": e2ee.Bytes(inv.AuthKey), "acceptance": acceptance(t, "ZZZZZZZZ", member.ID, member.Identity)}), http.StatusUnprocessableEntity, "wrong_user")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", member.Token, map[string]any{"authKey": e2ee.Bytes(inv.AuthKey), "acceptance": acceptance(t, inv.ID, member.ID, newIdentity())}), http.StatusUnprocessableEntity, "bad_signature")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", member.Token, map[string]any{"authKey": e2ee.Bytes(make([]byte, 32)), "acceptance": acceptance(t, inv.ID, member.ID, member.Identity)}), http.StatusUnauthorized, "bad_auth_key")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", inviter.Token, map[string]any{"authKey": e2ee.Bytes(inv.AuthKey), "acceptance": acceptance(t, inv.ID, inviter.ID, inviter.Identity)}), http.StatusForbidden, "own_invite")
	blocker := e.newUser("Blocker")
	e.block(inviter, blocker)
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", blocker.Token, map[string]any{"authKey": e2ee.Bytes(inv.AuthKey), "acceptance": acceptance(t, inv.ID, blocker.ID, blocker.Identity)}), http.StatusForbidden, "blocked")

	// Sign-up rules.
	signup := e.signupToken("new@example.org")
	identity := newIdentity()
	uid := ids.NewV7().String()
	signupBody := func(token, userID string) map[string]any {
		return map[string]any{
			"authKey":    e2ee.Bytes(inv.AuthKey),
			"acceptance": acceptance(t, inv.ID, userID, identity),
			"signup":     map[string]any{"signupToken": token, "userId": userID, "displayName": "New"},
		}
	}
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", member.Token, signupBody(signup, uid)), http.StatusBadRequest, "bad_request") // both
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", "", signupBody("nope", uid)), http.StatusUnauthorized, "invalid_token")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", "", signupBody(signup, member.ID)), http.StatusConflict, "user_exists")
	// A failed redemption does not use up the sign-up token.
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", "", signupBody(signup, uid)), http.StatusOK, "")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", "", signupBody(signup, ids.NewV7().String())), http.StatusUnauthorized, "invalid_token")

	// Revoked and expired invites answer 410.
	e.want(e.call("DELETE", "/api/invites/"+inv.ID, member.Token, nil), http.StatusNotFound, "not_found")
	e.want(e.call("DELETE", "/api/invites/"+inv.ID, inviter.Token, nil), http.StatusNoContent, "")
	e.want(e.call("GET", "/api/invites/"+inv.ID, "", nil), http.StatusGone, "invite_revoked")
	late := e.newUser("Late")
	e.want(e.call("POST", "/api/invites/"+inv.ID+"/redeem", late.Token, map[string]any{"authKey": e2ee.Bytes(inv.AuthKey), "acceptance": acceptance(t, inv.ID, late.ID, late.Identity)}), http.StatusGone, "invite_revoked")
	short := makeInvite(t, inviter, e.clock().Add(time.Hour))
	e.want(e.call("POST", "/api/invites", inviter.Token, short.Body), http.StatusCreated, "")
	e.advance(2 * time.Hour)
	e.want(e.call("GET", "/api/invites/"+short.ID, "", nil), http.StatusGone, "invite_expired")
	e.want(e.call("POST", "/api/invites/"+short.ID+"/redeem", late.Token, map[string]any{"authKey": e2ee.Bytes(short.AuthKey), "acceptance": acceptance(t, short.ID, late.ID, late.Identity)}), http.StatusGone, "invite_expired")
	e.want(e.call("GET", "/api/invites/"+inv.ID+"/redemptions", member.Token, nil), http.StatusNotFound, "not_found")
}

func signedStreak(t *testing.T, u *user, practice string, seq int64, day string, current int) map[string]any {
	payload, err := e2ee.Marshal(e2ee.Streak{Current: current, Day: day, Deadline: 1_760_000_000_000, Longest: current + 1, Practice: practice, Seq: seq, User: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"payload": e2ee.Bytes(payload), "signature": e2ee.Bytes(e2ee.SignStatement(u.Identity, e2ee.TypeStreak, payload))}
}

func (e *env) pushToken(u *user, token string) {
	e.t.Helper()
	e.registerDevice(u, newDevice(e.t))
	e.want(e.call("PUT", "/api/push-tokens", u.Token, map[string]any{"platform": "apns", "token": token}), http.StatusNoContent, "")
}

func TestStreaks(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	friend := e.newUser("Dolma")
	stranger := e.newUser("Stranger")
	e.befriend(u, friend)
	e.befriend(u, stranger)
	e.pushToken(friend, "friend-token")
	e.pushToken(stranger, "stranger-token")
	e.block(stranger, u)

	r := e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "dorje-sempa", 1, "2026-10-03", 41))
	e.want(r, http.StatusOK, "")
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "dorje-sempa", 1, "2026-10-04", 42)), http.StatusConflict, "stale_seq")
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "dorje-sempa", 2, "2026-10-04", 42)), http.StatusOK, "")
	// Same day again: no second push.
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "dorje-sempa", 3, "2026-10-04", 42)), http.StatusOK, "")

	pushes := e.push.all()
	if len(pushes) != 2 {
		t.Fatalf("pushes %+v", pushes)
	}
	last := pushes[1]
	if len(last.Tokens) != 1 || last.Tokens[0].Token != "friend-token" {
		t.Fatalf("pushed to %+v (blocked friends get nothing)", last.Tokens)
	}
	want := push.DoneToday("Tenzin", "dorje-sempa", 42, "2026-10-04")
	if last.N.LocKey != push.LocDoneToday || strings.Join(last.N.LocArgs, "|") != strings.Join(want.LocArgs, "|") {
		t.Fatalf("notification %+v", last.N)
	}

	// Validation.
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, friend, "dorje-sempa", 9, "2026-10-04", 1)), http.StatusUnprocessableEntity, "bad_signature")
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, &user{ID: friend.ID, Identity: u.Identity}, "dorje-sempa", 9, "2026-10-04", 1)), http.StatusUnprocessableEntity, "wrong_user")
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "Dorje Sempa", 9, "2026-10-04", 1)), http.StatusBadRequest, "bad_request")
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "chenrezig", 9, "2026-13-04", 1)), http.StatusBadRequest, "bad_request")
	e.want(e.call("PUT", "/api/streaks", u.Token, signedStreak(t, u, "chenrezig", 9, "2026-10-04", -1)), http.StatusBadRequest, "bad_request")

	var sts []streakJSON
	r = e.call("GET", "/api/friends/streaks", friend.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &sts)
	if len(sts) != 1 || sts[0].Seq != 3 || sts[0].User != u.ID || !e2ee.VerifyStatement(u.Identity.Public().(ed25519.PublicKey), e2ee.TypeStreak, sts[0].Payload, sts[0].Signature) {
		t.Fatalf("friend streaks %s", r.Body)
	}
	sts = nil
	e.call("GET", "/api/friends/streaks", stranger.Token, nil).json(t, &sts)
	if len(sts) != 0 {
		t.Fatal("blocked friend sees streaks")
	}
	sts = nil
	e.call("GET", "/api/friends/streaks", e.newUser("Nobody").Token, nil).json(t, &sts)
	if len(sts) != 0 {
		t.Fatal("stranger sees streaks")
	}

	e.want(e.call("DELETE", "/api/streaks/dorje-sempa", u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("DELETE", "/api/streaks/Bad Key", u.Token, nil), http.StatusBadRequest, "bad_request")
	sts = nil
	e.call("GET", "/api/friends/streaks", friend.Token, nil).json(t, &sts)
	if len(sts) != 0 {
		t.Fatal("unpublished streak still served")
	}
}

func TestFriendsBlocksReports(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	f := e.newUser("Dolma")
	e.befriend(u, f)

	e.want(e.call("PUT", "/api/blocks/"+f.ID, u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("PUT", "/api/blocks/"+f.ID, u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("PUT", "/api/blocks/"+u.ID, u.Token, nil), http.StatusBadRequest, "bad_request")
	e.want(e.call("PUT", "/api/blocks/"+ids.NewV7().String(), u.Token, nil), http.StatusNotFound, "not_found")
	var blocks []struct {
		UserID string `json:"userId"`
	}
	e.call("GET", "/api/blocks", u.Token, nil).json(t, &blocks)
	if len(blocks) != 1 || blocks[0].UserID != f.ID {
		t.Fatalf("blocks %v", blocks)
	}
	var friends []struct {
		UserID  string `json:"userId"`
		Blocked bool   `json:"blocked"`
	}
	e.call("GET", "/api/friends", u.Token, nil).json(t, &friends)
	if len(friends) != 1 || !friends[0].Blocked {
		t.Fatalf("friends %v", friends)
	}
	e.want(e.call("DELETE", "/api/blocks/"+f.ID, u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("DELETE", "/api/blocks/"+f.ID, u.Token, nil), http.StatusNoContent, "")

	e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": f.ID, "reason": "name", "note": "Not a name"}), http.StatusCreated, "")
	e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": f.ID, "reason": "rude"}), http.StatusBadRequest, "bad_request")
	e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": u.ID, "reason": "spam"}), http.StatusBadRequest, "bad_request")
	e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": ids.NewV7().String(), "reason": "spam"}), http.StatusNotFound, "not_found")
	e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": f.ID, "reason": "other", "note": strings.Repeat("x", 1001)}), http.StatusBadRequest, "bad_request")
	for i := 0; i < 9; i++ {
		e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": f.ID, "reason": "spam"}), http.StatusCreated, "")
	}
	e.want(e.call("POST", "/api/reports", u.Token, map[string]any{"userId": f.ID, "reason": "spam"}), http.StatusTooManyRequests, "rate_limited")

	e.want(e.call("DELETE", "/api/friends/"+f.ID, u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("DELETE", "/api/friends/"+f.ID, u.Token, nil), http.StatusNotFound, "not_found")
	friends = nil
	e.call("GET", "/api/friends", f.Token, nil).json(t, &friends)
	if len(friends) != 0 {
		t.Fatal("unfriend is not symmetric")
	}
}

func TestPushTokensAndPoke(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	f := e.newUser("Dolma")

	e.want(e.call("PUT", "/api/push-tokens", u.Token, map[string]any{"platform": "apns", "token": "t"}), http.StatusConflict, "no_device")
	e.registerDevice(u, newDevice(t))
	e.want(e.call("PUT", "/api/push-tokens", u.Token, map[string]any{"platform": "webpush", "token": "t"}), http.StatusBadRequest, "bad_request")
	e.want(e.call("PUT", "/api/push-tokens", u.Token, map[string]any{"platform": "fcm", "token": ""}), http.StatusBadRequest, "bad_request")
	e.pushToken(f, "dolma-token")

	e.want(e.call("POST", "/api/nudges/poke/"+f.ID, u.Token, nil), http.StatusNotFound, "not_found") // not friends
	e.befriend(u, f)
	e.want(e.call("POST", "/api/nudges/poke/"+f.ID, u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("POST", "/api/nudges/poke/"+f.ID, u.Token, nil), http.StatusTooManyRequests, "already_poked")
	pushes := e.push.all()
	if len(pushes) != 1 || pushes[0].N.LocKey != push.LocPoke || len(pushes[0].N.LocArgs) != 1 || pushes[0].N.LocArgs[0] != "Tenzin" || pushes[0].Tokens[0].Token != "dolma-token" {
		t.Fatalf("pushes %+v", pushes)
	}
	// The friend may poke back the same day; a new UTC day allows another.
	e.want(e.call("POST", "/api/nudges/poke/"+u.ID, f.Token, nil), http.StatusNoContent, "")
	e.advance(24 * time.Hour)
	e.want(e.call("POST", "/api/nudges/poke/"+f.ID, u.Token, nil), http.StatusNoContent, "")
	// Never across a block, in either direction.
	e.advance(24 * time.Hour)
	e.block(f, u)
	e.want(e.call("POST", "/api/nudges/poke/"+f.ID, u.Token, nil), http.StatusNotFound, "not_found")

	// Deleting the token stops pushes.
	e.want(e.call("DELETE", "/api/push-tokens", f.Token, nil), http.StatusNoContent, "")
	tokens, err := e.store.PushTokens(t.Context(), []string{f.ID})
	if err != nil || len(tokens) != 0 {
		t.Fatalf("tokens %v %v", tokens, err)
	}
}
