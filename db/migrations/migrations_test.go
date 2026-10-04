// Package migrations_test checks that every migration's version is a real,
// generator-stamped UTC timestamp rather than one hand-typed to look plausible.
//
// Ported from CodeShare (codeshare-api), itself a port of holy-shit-api's and
// vq/knowledge-base's; keep it close enough to diff against them. There are no
// legacy sequential versions here, so no exemptions.
//
// A hand-typed version gets renumbered once the ordering turns out wrong, and every
// environment that already ran the old number keeps a goose_db_version row for a
// version that no longer exists. The fix is always to delete the file and re-run
// `make db-new name=<name>` (goose create), never to hand-edit a timestamp into place,
// and never to rename a migration that has been deployed.
package migrations_test

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

var filenamePattern = regexp.MustCompile(`^(\d{14})_\w+\.(sql|go)$`)

// clockSkewAllowance allows a generator running on a clock slightly ahead of this
// test's.
const clockSkewAllowance = time.Hour

// roundTimestampOverride, set non-empty, allows a version ending in "0000": the
// generator stamps a round second about once in 3600.
const roundTimestampOverride = "ALLOW_ROUND_MIGRATION_TIMESTAMP"

func TestMigrationVersionsAreReal(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading db/migrations: %v", err)
	}

	seen := map[string]string{}
	now := time.Now().UTC()

	for _, entry := range entries {
		// Only this package's own files are exempt. Any other .go file would be a goose
		// Go migration, which needs a real version just as much as a .sql one.
		if entry.IsDir() || entry.Name() == "embed.go" || entry.Name() == "migrations_test.go" {
			continue
		}
		name := entry.Name()

		match := filenamePattern.FindStringSubmatch(name)
		if match == nil {
			t.Errorf("%s: is not named <14-digit version>_<name>.sql (or .go) -- create migrations with "+
				"`make db-new name=<name>`, not by numbering them by hand", name)
			continue
		}
		version := match[1]

		at, ok := parseUTCInstant(version)
		if !ok {
			t.Errorf("%s: %s is not a real UTC instant under YYYYMMDDHHMMSS", name, version)
			continue
		}
		if at.After(now.Add(clockSkewAllowance)) {
			t.Errorf("%s: %s is in the future (now is %s UTC, and %d minutes of clock skew is allowed)",
				name, version, now.Format("20060102150405"), int(clockSkewAllowance.Minutes()))
		}
		if os.Getenv(roundTimestampOverride) == "" && version[10:] == "0000" {
			t.Errorf("%s: %s ends in 0000, which the generator stamps about once in 3600 -- "+
				"if this really came from `goose create`, set %s", name, version, roundTimestampOverride)
		}

		if other, ok := seen[version]; ok {
			t.Errorf("%s: %s is already taken by %s, and a version identifies a migration", name, version, other)
			continue
		}
		seen[version] = name
	}
}

func parseUTCInstant(version string) (time.Time, bool) {
	if len(version) != 14 {
		return time.Time{}, false
	}
	year, err1 := strconv.Atoi(version[0:4])
	month, err2 := strconv.Atoi(version[4:6])
	day, err3 := strconv.Atoi(version[6:8])
	hour, err4 := strconv.Atoi(version[8:10])
	minute, err5 := strconv.Atoi(version[10:12])
	second, err6 := strconv.Atoi(version[12:14])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil {
		return time.Time{}, false
	}
	if hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	at := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	// time.Date normalizes an impossible calendar date (month 13, day 32) into a
	// different one instead of failing; round-tripping catches that.
	if at.Year() != year || int(at.Month()) != month || at.Day() != day {
		return time.Time{}, false
	}
	return at, true
}
