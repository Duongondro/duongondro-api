package names

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestLists(t *testing.T) {
	for name, words := range map[string][]string{"adjectives": Adjectives, "animals": Animals} {
		seen := map[string]bool{}
		for _, w := range words {
			r, _ := utf8.DecodeRuneInString(w)
			if !unicode.IsUpper(r) || strings.TrimSpace(w) != w || seen[w] {
				t.Errorf("%s: %q", name, w)
			}
			seen[w] = true
		}
	}
	if len(Adjectives) != 124 || len(Animals) != 113 {
		t.Fatalf("%d adjectives, %d animals: not CodeShare's lists", len(Adjectives), len(Animals))
	}
}

func TestRandom(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		name, err := Random()
		if err != nil {
			t.Fatal(err)
		}
		adj, animal, ok := strings.Cut(name, " ")
		if !ok || !slices.Contains(Adjectives, adj) || !slices.Contains(Animals, animal) || len(name) > 64 {
			t.Fatalf("%q is not an adjective and an animal", name)
		}
		seen[name] = true
	}
	if len(seen) < 150 {
		t.Fatalf("only %d distinct names in 200 draws", len(seen))
	}
}
