package streak

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type caseFile struct {
	Name string `json:"name"`
	Seed *struct {
		Days    int    `json:"days"`
		LastDay string `json:"lastDay"`
		TZ      string `json:"tz"`
	} `json:"seed"`
	Events []struct {
		Kind  Kind   `json:"kind"`
		Start string `json:"start"`
		TZ    string `json:"tz"`
		Day   string `json:"day"`
	} `json:"events"`
	Now    string `json:"now"`
	NowTZ  string `json:"nowTz"`
	Expect struct {
		Current        int     `json:"current"`
		CurrentTracked int     `json:"currentTracked"`
		Longest        int     `json:"longest"`
		LongestTracked int     `json:"longestTracked"`
		LastDay        *string `json:"lastDay"`
		Deadline       *string `json:"deadline"`
	} `json:"expect"`
}

func TestConformanceCases(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/streak-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []caseFile
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 15 {
		t.Fatalf("expected the full case set, got %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			in := Input{NowTZ: c.NowTZ, Now: mustTime(t, c.Now)}
			if c.Seed != nil {
				in.Seed = &Seed{Days: c.Seed.Days, LastDay: c.Seed.LastDay, TZ: c.Seed.TZ}
			}
			for _, e := range c.Events {
				ev := Event{Kind: e.Kind, TZ: e.TZ, Day: e.Day}
				if e.Start != "" {
					ev.Start = mustTime(t, e.Start)
				}
				in.Events = append(in.Events, ev)
			}
			got, err := Compute(in)
			if err != nil {
				t.Fatal(err)
			}
			want := c.Expect
			if got.Current != want.Current || got.CurrentTracked != want.CurrentTracked ||
				got.Longest != want.Longest || got.LongestTracked != want.LongestTracked {
				t.Errorf("counts: got current %d/%d longest %d/%d, want %d/%d %d/%d",
					got.Current, got.CurrentTracked, got.Longest, got.LongestTracked,
					want.Current, want.CurrentTracked, want.Longest, want.LongestTracked)
			}
			if want.LastDay == nil {
				if got.LastDay != "" || !got.Deadline.IsZero() {
					t.Errorf("expected nothing started, got lastDay %q deadline %v", got.LastDay, got.Deadline)
				}
				return
			}
			if got.LastDay != *want.LastDay {
				t.Errorf("lastDay: got %s, want %s", got.LastDay, *want.LastDay)
			}
			if d := got.Deadline.Format(time.RFC3339); d != *want.Deadline {
				t.Errorf("deadline: got %s, want %s", d, *want.Deadline)
			}
		})
	}
}

func TestCivilDateIgnoresWeekYear(t *testing.T) {
	warsaw, _ := time.LoadLocation("Europe/Warsaw")
	d := CivilDate(mustTime(t, "2025-12-29T08:00:00+01:00"), warsaw)
	if d.String() != "2025-12-29" {
		t.Fatalf("got %s", d)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
