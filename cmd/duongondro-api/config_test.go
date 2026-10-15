package main

import "testing"

// An env file from before sign-up was always open still starts, whatever it sets
// OPEN_SIGNUP to.
func TestObsoleteOpenSignUpIsIgnored(t *testing.T) {
	t.Setenv("RP_ID", "duongondro.app")
	t.Setenv("RP_ORIGINS", "https://duongondro.app")
	for _, v := range []string{"true", "false", "not a boolean"} {
		t.Setenv("OPEN_SIGNUP", v)
		if _, err := loadConfig(); err != nil {
			t.Fatalf("OPEN_SIGNUP=%q: %v", v, err)
		}
	}
}
