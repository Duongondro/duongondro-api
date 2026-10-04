// Package streak is the reference implementation of docs/streaks.md.
//
// It exists so that the iOS and Android implementations have a referee:
// testdata/streak-cases.json is checked here and by both clients, unchanged.
package streak

import (
	"fmt"
	"sort"
	"time"
	_ "time/tzdata" // the cases must not depend on the host's zone database
)

// Kind of an event.
type Kind string

const (
	Session Kind = "session"
	Bardo   Kind = "bardo"
)

// Event is a logged session or a bardo day.
type Event struct {
	Kind  Kind
	Start time.Time // sessions only
	TZ    string    // IANA zone the phone was in
	Day   string    // optional for sessions (the user's choice), required for bardo days
}

// Seed is an imported streak.
type Seed struct {
	Days    int
	LastDay string
	TZ      string
}

// Input to Compute.
type Input struct {
	Events []Event
	Seed   *Seed
	Now    time.Time
	NowTZ  string
}

// Result of Compute. LastDay and Deadline are zero when nothing has started.
type Result struct {
	Current        int
	CurrentTracked int
	Longest        int
	LongestTracked int
	LastDay        string
	Deadline       time.Time
}

// Date is a civil (Gregorian) date.
type Date struct{ Year, Month, Day int }

// ParseDate parses YYYY-MM-DD.
func ParseDate(s string) (Date, error) {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return Date{}, fmt.Errorf("streak: bad date %q: %w", s, err)
	}
	return Date{t.Year(), int(t.Month()), t.Day()}, nil
}

func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day) }

func (d Date) less(o Date) bool {
	if d.Year != o.Year {
		return d.Year < o.Year
	}
	if d.Month != o.Month {
		return d.Month < o.Month
	}
	return d.Day < o.Day
}

// CivilDate is the Gregorian date of t in loc.
func CivilDate(t time.Time, loc *time.Location) Date {
	y, m, d := t.In(loc).Date()
	return Date{y, int(m), d}
}

// StartOfDay is the first instant of civil date d plus offset days in loc.
// time.Date normalises a midnight that falls in a DST gap to the first instant
// that exists, as the spec requires.
func StartOfDay(d Date, offset int, loc *time.Location) time.Time {
	return time.Date(d.Year, time.Month(d.Month), d.Day+offset, 0, 0, 0, 0, loc)
}

type event struct {
	kind  Kind
	day   Date
	loc   *time.Location
	at    time.Time // effective instant
	index int
}

// Compute evaluates the streak described by in.
func Compute(in Input) (Result, error) {
	evs := make([]event, 0, len(in.Events))
	for i, e := range in.Events {
		loc, err := time.LoadLocation(e.TZ)
		if err != nil {
			return Result{}, fmt.Errorf("streak: event %d: %w", i, err)
		}
		ev := event{kind: e.Kind, loc: loc, index: i}
		switch e.Kind {
		case Session:
			ev.day = CivilDate(e.Start, loc)
			ev.at = e.Start
			if e.Day != "" {
				if ev.day, err = ParseDate(e.Day); err != nil {
					return Result{}, err
				}
				if last := StartOfDay(ev.day, 1, loc).Add(-time.Second); last.Before(ev.at) {
					ev.at = last
				}
			}
		case Bardo:
			if ev.day, err = ParseDate(e.Day); err != nil {
				return Result{}, err
			}
			ev.at = StartOfDay(ev.day, 0, loc)
		default:
			return Result{}, fmt.Errorf("streak: event %d: unknown kind %q", i, e.Kind)
		}
		evs = append(evs, ev)
	}
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		if a.kind != b.kind {
			return a.kind == Session
		}
		return a.index < b.index
	})

	var (
		r       Result
		started bool
		count   int
		tracked int
		lastDay Date
		zones   []*time.Location
	)
	note := func() {
		r.Longest = max(r.Longest, count)
		r.LongestTracked = max(r.LongestTracked, tracked)
	}
	addZone := func(z *time.Location) {
		for _, x := range zones {
			if x.String() == z.String() {
				return
			}
		}
		zones = append(zones, z)
	}
	if in.Seed != nil {
		loc, err := time.LoadLocation(in.Seed.TZ)
		if err != nil {
			return Result{}, fmt.Errorf("streak: seed: %w", err)
		}
		if lastDay, err = ParseDate(in.Seed.LastDay); err != nil {
			return Result{}, err
		}
		started, count, tracked, zones = true, in.Seed.Days, 0, []*time.Location{loc}
		note()
	}

	for _, e := range evs {
		switch {
		case !started:
			if e.kind == Session {
				started, count, tracked, lastDay, zones = true, 1, 1, e.day, []*time.Location{e.loc}
			}
		case !lastDay.less(e.day): // same date, or an earlier one after flying west
			addZone(e.loc)
		case e.at.Before(deadline(lastDay, zones, e.loc)):
			if e.kind == Session {
				count++
				tracked++
			}
			lastDay, zones = e.day, []*time.Location{e.loc}
		default:
			if e.kind == Session {
				count, tracked, lastDay, zones = 1, 1, e.day, []*time.Location{e.loc}
			} else {
				started, count, tracked, zones = false, 0, 0, nil
			}
		}
		note()
	}

	if !started {
		return r, nil
	}
	nowLoc, err := time.LoadLocation(in.NowTZ)
	if err != nil {
		return Result{}, fmt.Errorf("streak: nowTz: %w", err)
	}
	r.LastDay = lastDay.String()
	r.Deadline = deadline(lastDay, zones, nowLoc).UTC()
	if in.Now.Before(r.Deadline) {
		r.Current, r.CurrentTracked = count, tracked
	}
	return r, nil
}

// deadline is midnight at the end of the day after d, in whichever of the
// zones (plus the viewing zone) gives the most time.
func deadline(d Date, zones []*time.Location, from *time.Location) time.Time {
	best := StartOfDay(d, 2, from)
	for _, z := range zones {
		if t := StartOfDay(d, 2, z); t.After(best) {
			best = t
		}
	}
	return best
}
