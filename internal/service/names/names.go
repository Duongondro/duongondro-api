// Package names draws the anonymous display name an account gets when it signs up
// without one: a random English "Adjective Animal" in title case, such as
// "Tidy Otter", as CodeShare names its anonymous members (the owner decided on
// English only).
//
// adjectives.json and animals.json are the English ("en") entries of CodeShare's
// testdata/names/adjectives.json and animals.json (CodeShareApp/codeshare-api at
// edf2461, 14 October 2026), in the same order. A few animals are two words
// ("Sea Otter"), so a name is an adjective, a space, and an animal.
package names

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"math/big"
	"strings"
	"unicode"
)

var (
	//go:embed adjectives.json
	adjectivesJSON []byte
	//go:embed animals.json
	animalsJSON []byte

	// Adjectives and Animals are the word lists, read once at start.
	Adjectives = mustList(adjectivesJSON)
	Animals    = mustList(animalsJSON)
)

func mustList(raw []byte) []string {
	var words []string
	if err := json.Unmarshal(raw, &words); err != nil || len(words) == 0 {
		panic("names: a word list is malformed or empty")
	}
	return words
}

// Random draws a name with crypto/rand: one adjective and one animal, uniformly.
func Random() (string, error) {
	adj, err := pick(Adjectives)
	if err != nil {
		return "", err
	}
	animal, err := pick(Animals)
	if err != nil {
		return "", err
	}
	return adj + " " + animal, nil
}

func pick(words []string) (string, error) {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
	if err != nil {
		return "", err
	}
	return words[i.Int64()], nil
}

// Clean trims a display name of white space and invisible format characters (Cf,
// such as zero-width spaces and direction marks) at both ends, and returns "" for a
// name with no letter, number or symbol left in it: such a name shows as blank, so
// it counts as none (a random name at sign-up, the unnamed keys in pushes).
func Clean(name string) string {
	name = strings.TrimFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) })
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsSymbol(r) {
			return name
		}
	}
	return ""
}
