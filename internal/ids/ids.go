// Package ids parses and makes the identifiers the API uses: UUIDs (v7 for
// anything a phone creates), Crockford base32 invite ids and bearer tokens.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// UUID is the 16 raw bytes of a UUID.
type UUID [16]byte

var errUUID = errors.New("ids: not a UUID")

// ParseUUID accepts the canonical 36-character form, in either case.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, errUUID
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, errUUID
	}
	return u, nil
}

// String is the canonical lowercase form.
func (u UUID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], u[10:16])
	return string(b[:])
}

// IsV7 reports whether u is a version 7, RFC 9562 variant UUID.
func (u UUID) IsV7() bool { return u[6]>>4 == 7 && u[8]>>6 == 0b10 }

// Hash is SHA-256 of the 16 raw bytes, as stored in purge_log.
func (u UUID) Hash() []byte {
	h := sha256.Sum256(u[:])
	return h[:]
}

// NewV7 makes a UUIDv7 from the current time (PostgreSQL 16 has no
// uuidv7()).
func NewV7() UUID { return newV7(time.Now()) }

func newV7(t time.Time) UUID {
	var u UUID
	_, _ = rand.Read(u[:])
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(t.UnixMilli()))
	copy(u[0:6], ms[2:8])
	u[6] = u[6]&0x0f | 0x70
	u[8] = u[8]&0x3f | 0x80
	return u
}

// CanonicalUUID parses s and returns its canonical lowercase form.
func CanonicalUUID(s string) (string, bool) {
	u, err := ParseUUID(s)
	if err != nil {
		return "", false
	}
	return u.String(), true
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// InviteID normalises an 8-character Crockford base32 invite id to
// uppercase. Ambiguous letters (I, L, O, U) are refused rather than mapped,
// since the apps never produce them.
func InviteID(s string) (string, bool) {
	if len(s) != 8 {
		return "", false
	}
	up := strings.ToUpper(s)
	for i := 0; i < len(up); i++ {
		if strings.IndexByte(crockford, up[i]) < 0 {
			return "", false
		}
	}
	return up, true
}

// NewInviteID returns a random 8-character id (40 bits).
func NewInviteID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, 8)
	for i := range out {
		out[i] = crockford[b[i]&31]
	}
	return string(out)
}

// NewToken returns a random 32-byte token as unpadded base64url and its
// SHA-256, which is all the server stores.
func NewToken() (token string, hash []byte) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	token = base64.RawURLEncoding.EncodeToString(b[:])
	return token, HashToken(token)
}

// HashToken is SHA-256 of the token string as presented.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
