package service

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Duongondro/duongondro-api/internal/db"
)

func ptr[T any](v T) *T { return &v }

func TestProfile(t *testing.T) {
	f := setup(t)
	s := NewSocial(f.pool)
	ctx := t.Context()
	ana, bo := f.member(), f.member()

	if err := s.UpdateProfile(ctx, ana.ID, ProfileUpdate{DisplayName: ptr(" Ana "), SetUsername: true, Username: ptr("Ana.B_1"),
		SetGender: true, Gender: ptr("female")}); err != nil {
		t.Fatal(err)
	}
	got := f.reload(ana.User)
	if got.DisplayName != "Ana" || got.Username == nil || *got.Username != "ana.b_1" || got.Gender == nil || *got.Gender != "female" {
		t.Fatalf("profile %q %v %v", got.DisplayName, got.Username, got.Gender)
	}
	// Usernames are unique regardless of case.
	if err := s.UpdateProfile(ctx, bo.ID, ProfileUpdate{SetUsername: true, Username: ptr("ANA.B_1")}); !isConflict(err) {
		t.Fatalf("a taken username: %v", err)
	}
	for _, bad := range []string{"ab", "a b c", "ana-b", "żaneta", "", "a234567890123456789012345678901234"} {
		if err := s.UpdateProfile(ctx, bo.ID, ProfileUpdate{SetUsername: true, Username: ptr(bad)}); !isValidation(err) {
			t.Errorf("username %q: %v", bad, err)
		}
	}
	if err := s.UpdateProfile(ctx, bo.ID, ProfileUpdate{SetGender: true, Gender: ptr("other")}); !isValidation(err) {
		t.Fatalf("an unknown gender: %v", err)
	}
	// Absent fields stay; the display name alone, as the iOS app sends it, changes only it.
	if err := s.UpdateProfile(ctx, ana.ID, ProfileUpdate{DisplayName: ptr("Ania")}); err != nil {
		t.Fatal(err)
	}
	got = f.reload(ana.User)
	if got.DisplayName != "Ania" || got.Username == nil || got.Gender == nil {
		t.Fatalf("a display-name update touched the rest: %v %v", got.Username, got.Gender)
	}
	// Friends see the gender, not the username.
	if err := s.q.Befriend(ctx, db.BefriendParams{UserID: ana.ID, FriendID: bo.ID}); err != nil {
		t.Fatal(err)
	}
	friends, err := s.Friends(ctx, bo.ID)
	if err != nil || len(friends) != 1 || friends[0].Gender == nil || *friends[0].Gender != "female" {
		t.Fatalf("friends: %v %+v", err, friends)
	}
	// A passkey added now is named after the username and display name.
	signIn, _ := f.signIn(nil, nil, nil)
	c, err := signIn.BeginPasskeyAdd(ctx, ana.ID)
	if err != nil {
		t.Fatal(err)
	}
	user := c.Options.(*protocol.CredentialCreation).Response.User
	if user.Name != "ana.b_1" || user.DisplayName != "Ania" {
		t.Fatalf("passkey user %q / %q", user.Name, user.DisplayName)
	}
	// Null clears; the username is then free for someone else.
	if err := s.UpdateProfile(ctx, ana.ID, ProfileUpdate{SetUsername: true, SetGender: true}); err != nil {
		t.Fatal(err)
	}
	got = f.reload(ana.User)
	if got.Username != nil || got.Gender != nil || got.DisplayName != "Ania" {
		t.Fatalf("cleared: %v %v %q", got.Username, got.Gender, got.DisplayName)
	}
	if err := s.UpdateProfile(ctx, bo.ID, ProfileUpdate{SetUsername: true, Username: ptr("ana.b_1")}); err != nil {
		t.Fatalf("a freed username: %v", err)
	}
	// Without a username the display name names the passkey; without either, the app.
	c, _ = signIn.BeginPasskeyAdd(ctx, ana.ID)
	if user := c.Options.(*protocol.CredentialCreation).Response.User; user.Name != "Ania" {
		t.Fatalf("passkey name without a username: %q", user.Name)
	}
	plain := f.member()
	c, _ = signIn.BeginPasskeyAdd(ctx, plain.ID)
	if user := c.Options.(*protocol.CredentialCreation).Response.User; user.Name != "Duongöndro" || user.DisplayName != "Duongöndro" {
		t.Fatalf("passkey names without a profile: %q / %q", user.Name, user.DisplayName)
	}
}

// A passkey sign-up may carry the profile: it names the passkey and lands on the new
// account; a taken username is a conflict when the ceremony begins or finishes.
func TestPasskeySignUpWithProfile(t *testing.T) {
	f := setup(t)
	s, social := f.signIn(nil, nil, nil)
	ctx := t.Context()
	taken := f.member()
	if err := social.UpdateProfile(ctx, taken.ID, ProfileUpdate{SetUsername: true, Username: ptr("taken")}); err != nil {
		t.Fatal(err)
	}
	code, _ := f.admissionCode(time.Hour)
	proof := SignUpProof{AdmissionCode: code}

	if _, err := s.BeginPasskeySignUp(ctx, proof, SignUpProfile{Username: ptr("TAKEN")}); !isConflict(err) {
		t.Fatalf("a taken username at begin: %v", err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, proof, SignUpProfile{Username: ptr("x")}); !isValidation(err) {
		t.Fatalf("a malformed username: %v", err)
	}
	if _, err := s.BeginPasskeySignUp(ctx, proof, SignUpProfile{Gender: ptr("robot")}); !isValidation(err) {
		t.Fatalf("an unknown gender: %v", err)
	}

	// Taken between begin and finish: a conflict, no account, and the code unspent.
	c, err := s.BeginPasskeySignUp(ctx, proof, SignUpProfile{Username: ptr("Racer")})
	if err != nil {
		t.Fatal(err)
	}
	if err := social.UpdateProfile(ctx, taken.ID, ProfileUpdate{SetUsername: true, Username: ptr("racer")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options)); !isConflict(err) {
		t.Fatalf("a username taken during the ceremony: %v", err)
	}

	c, err = s.BeginPasskeySignUp(ctx, proof, SignUpProfile{Username: ptr("Cy.K"), DisplayName: ptr(" Cy "), Gender: ptr("nonbinary")})
	if err != nil {
		t.Fatalf("the code was spent by a failed sign-up: %v", err)
	}
	user := c.Options.(*protocol.CredentialCreation).Response.User
	if user.Name != "cy.k" || user.DisplayName != "Cy" {
		t.Fatalf("passkey user %q / %q", user.Name, user.DisplayName)
	}
	session, err := s.FinishPasskey(ctx, c.SessionID, newAuthenticator().create(t, c.Options))
	if err != nil || !session.Created {
		t.Fatalf("sign-up with a profile: %v", err)
	}
	got, err := f.q.GetUser(ctx, session.UserID)
	if err != nil || got.Username == nil || *got.Username != "cy.k" || got.DisplayName != "Cy" || got.Gender == nil || *got.Gender != "nonbinary" {
		t.Fatalf("the new account's profile: %v %v %q %v", err, got.Username, got.DisplayName, got.Gender)
	}
}
