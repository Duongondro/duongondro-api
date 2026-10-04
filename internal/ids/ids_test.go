package ids

import (
	"testing"
	"time"
)

func TestUUIDRoundTrip(t *testing.T) {
	const s = "0190F3A1-7B2C-7D4E-8F00-123456789ABC"
	u, err := ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "0190f3a1-7b2c-7d4e-8f00-123456789abc" {
		t.Fatalf("got %s", u)
	}
	if !u.IsV7() {
		t.Fatal("should be v7")
	}
	for _, bad := range []string{"", "0190f3a17b2c7d4e8f00123456789abc", "0190f3a1-7b2c-7d4e-8f00-123456789abg", "0190f3a1+7b2c-7d4e-8f00-123456789abc"} {
		if _, err := ParseUUID(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	v4, _ := ParseUUID("6f1c2a9e-3b4d-4e5f-9a0b-1c2d3e4f5a6b")
	if v4.IsV7() {
		t.Error("v4 accepted as v7")
	}
}

func TestNewV7(t *testing.T) {
	at := time.UnixMilli(1_700_000_000_123)
	u := newV7(at)
	if !u.IsV7() {
		t.Fatalf("not v7: %s", u)
	}
	ms := int64(u[0])<<40 | int64(u[1])<<32 | int64(u[2])<<24 | int64(u[3])<<16 | int64(u[4])<<8 | int64(u[5])
	if ms != at.UnixMilli() {
		t.Fatalf("timestamp %d", ms)
	}
	if NewV7() == NewV7() {
		t.Fatal("not random")
	}
}

func TestInviteID(t *testing.T) {
	if got, ok := InviteID("7k2mq9xa"); !ok || got != "7K2MQ9XA" {
		t.Fatalf("got %q %v", got, ok)
	}
	for _, bad := range []string{"7K2MQ9X", "7K2MQ9XAB", "7K2MQ9XI", "7K2MQ9XU", "7K2MQ9X-"} {
		if _, ok := InviteID(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, ok := InviteID(NewInviteID()); !ok {
		t.Fatal("NewInviteID not valid")
	}
}

func TestToken(t *testing.T) {
	tok, h := NewToken()
	if len(tok) != 43 || len(h) != 32 || string(HashToken(tok)) != string(h) {
		t.Fatalf("token %q", tok)
	}
}
