package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestFromSettings(t *testing.T) {
	clean := fromSettings("go1.24", []debug.BuildSetting{
		{Key: "vcs.revision", Value: "3f9c2e1a0b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"},
		{Key: "vcs.modified", Value: "false"},
		{Key: "vcs.time", Value: "2026-10-04T13:00:00Z"},
	})
	if clean.Short != "3f9c2e1" || clean.Modified {
		t.Fatalf("clean build: %+v", clean)
	}
	dirty := fromSettings("go1.24", []debug.BuildSetting{
		{Key: "vcs.revision", Value: "3f9c2e1a0b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"},
		{Key: "vcs.modified", Value: "true"},
	})
	if dirty.Short != "3f9c2e1-dirty" || !dirty.Modified {
		t.Fatalf("dirty build: %+v", dirty)
	}
	none := fromSettings("go1.24", nil)
	if none.Revision != "unknown" || none.Short != "unknown" {
		t.Fatalf("no vcs info: %+v", none)
	}
}
