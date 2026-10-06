package service

import (
	"testing"

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
