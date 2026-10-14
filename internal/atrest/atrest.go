// Package atrest encrypts the personal columns the server must be able to read, so
// that a database dump, a leaked backup or another project's role on the shared host
// reads none of them (docs/at-rest.md; design: Backend and sync › Encryption at
// rest, decision 17).
//
// It is the ChachaCrypter of homeosapiens-go, written here because go-sqlcrypter is
// not vendored: XChaCha20-Poly1305 with a random 24-byte nonce and the plaintext
// PKCS#7-padded to 32-byte blocks, keys derived from SECRET_KEY_BASE by
// HKDF-SHA512 (info "ColumnLevelEncryption" and "DatabaseHMAC"). Unlike
// go-sqlcrypter's Scan and Value, which see a value without its row, sealing here is
// explicit, so the AAD binds every value to its table, column, row and key: a value
// copied to another row, column or table does not open.
//
// Lookups go through blind indexes, HMAC-SHA256 under the DatabaseHMAC key of the
// normalised value (Hash). Equality is all they reveal.
package atrest

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"uuid"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"
)

const (
	// Format is the first byte of every sealed value.
	Format byte = 1
	// KeyIDSize is the size of the key id after the format byte: which
	// SECRET_KEY_BASE sealed the value (what the issue calls its key version).
	KeyIDSize = 4
	// PaddingBlock is the PKCS#7 block the plaintext is padded to, so a stored
	// length gives away a range, not the length of a name or address.
	PaddingBlock = 32
	// Overhead is what sealing adds besides the padding: format, key id, nonce, tag.
	Overhead = 1 + KeyIDSize + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	// HashSize is the size of a blind index.
	HashSize = sha256.Size
	// MinSecretKeyBase is the shortest SECRET_KEY_BASE accepted (decoded); 64 bytes
	// are recommended, as `openssl rand -base64 64` makes.
	MinSecretKeyBase = 32
)

// HKDF info strings, as in homeosapiens-go's config.
const (
	infoColumns = "ColumnLevelEncryption"
	infoHMAC    = "DatabaseHMAC"
	infoKeyID   = "ColumnLevelEncryptionKeyId"
)

const aadLabel = "duongondro/at-rest/v1"

// ErrOpen means a value did not open: unknown key, another row's or column's value,
// or tampering. It is a server error, never a client's.
var ErrOpen = errors.New("a sealed column did not open")

type key struct {
	id   [KeyIDSize]byte
	aead cipher.AEAD
	hmac []byte
}

func deriveKey(base []byte) (key, error) {
	if len(base) < MinSecretKeyBase {
		return key{}, fmt.Errorf("SECRET_KEY_BASE must decode to at least %d bytes, not %d", MinSecretKeyBase, len(base))
	}
	enc, err := DeriveKey(base, infoColumns, chacha20poly1305.KeySize)
	if err != nil {
		return key{}, err
	}
	mac, err := DeriveKey(base, infoHMAC, 32)
	if err != nil {
		return key{}, err
	}
	id, err := DeriveKey(base, infoKeyID, KeyIDSize)
	if err != nil {
		return key{}, err
	}
	aead, err := chacha20poly1305.NewX(enc)
	if err != nil {
		return key{}, err
	}
	k := key{aead: aead, hmac: mac}
	copy(k.id[:], id)
	return k, nil
}

// DeriveKey is HKDF-SHA512 with no salt, as homeosapiens-go's MustDeriveKey.
func DeriveKey(base []byte, info string, size int) ([]byte, error) {
	return hkdf.Key(sha512.New, base, nil, info, size)
}

// Keys seals and opens columns and computes blind indexes. Values are sealed and
// hashed under the current key; a previous key, kept while `duongondro-api reseal`
// (run by migrate) rewrites the rows, still opens what it sealed.
type Keys struct {
	current  key
	previous *key
}

// New derives the keys from SECRET_KEY_BASE (decoded) and, during a rotation, the
// previous one.
func New(base, previous []byte) (*Keys, error) {
	cur, err := deriveKey(base)
	if err != nil {
		return nil, err
	}
	k := &Keys{current: cur}
	if previous != nil {
		prev, err := deriveKey(previous)
		if err != nil {
			return nil, fmt.Errorf("SECRET_KEY_BASE_PREVIOUS: %w", err)
		}
		if prev.id == cur.id {
			return nil, errors.New("SECRET_KEY_BASE_PREVIOUS is the same key as SECRET_KEY_BASE")
		}
		k.previous = &prev
	}
	return k, nil
}

// FromEnv reads SECRET_KEY_BASE and the optional SECRET_KEY_BASE_PREVIOUS, both
// base64. Without SECRET_KEY_BASE it uses devDefault, which only DEV builds pass;
// release builds pass nil and refuse to start.
func FromEnv(getenv func(string) string, devDefault []byte) (*Keys, error) {
	decode := func(name string) ([]byte, error) {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return nil, nil
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%s is not base64: %w", name, err)
		}
		return b, nil
	}
	base, err := decode("SECRET_KEY_BASE")
	if err != nil {
		return nil, err
	}
	if base == nil {
		if devDefault == nil {
			return nil, errors.New("SECRET_KEY_BASE is not set: the personal columns are encrypted under it (README, Encryption at rest)")
		}
		base = devDefault
	}
	previous, err := decode("SECRET_KEY_BASE_PREVIOUS")
	if err != nil {
		return nil, err
	}
	return New(base, previous)
}

// Rotating reports whether a previous key is configured.
func (k *Keys) Rotating() bool { return k.previous != nil }

// KeyID is the current key's id, as stored after the format byte.
func (k *Keys) KeyID() [KeyIDSize]byte { return k.current.id }

// Column names a sealed column, as in the database.
type Column struct{ Table, Name string }

func (c Column) String() string { return c.Table + "." + c.Name }

// Row identifies the row a value belongs to: its primary key, as length-prefixed
// parts (RowOf). It must be known before the row is written and never change.
type Row []byte

// RowOf builds a Row from the parts of a primary key.
func RowOf(parts ...[]byte) Row {
	var r Row
	for _, p := range parts {
		r = binary.BigEndian.AppendUint16(r, uint16(len(p)))
		r = append(r, p...)
	}
	return r
}

// IDRow is the Row of a table keyed by one UUID.
func IDRow(id uuid.UUID) Row { return RowOf(id[:]) }

func aad(c Column, row Row, id [KeyIDSize]byte) []byte {
	out := []byte(aadLabel)
	for _, p := range [][]byte{[]byte(c.Table), []byte(c.Name), row} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
		out = append(out, p...)
	}
	out = append(out, Format)
	return append(out, id[:]...)
}

// Seal encrypts plaintext for column c of row:
//
//	Format ‖ keyID(4) ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, PKCS#7(plaintext, 32), aad)
//	aad = "duongondro/at-rest/v1" ‖ lp(table) ‖ lp(column) ‖ lp(row) ‖ Format ‖ keyID
//
// where lp is a 2-byte big-endian length and the bytes.
func (k *Keys) Seal(c Column, row Row, plaintext []byte) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	return k.sealWithNonce(c, row, plaintext, nonce)
}

func (k *Keys) sealWithNonce(c Column, row Row, plaintext, nonce []byte) []byte {
	out := make([]byte, 0, Overhead+len(plaintext)+PaddingBlock)
	out = append(out, Format)
	out = append(out, k.current.id[:]...)
	out = append(out, nonce...)
	return k.current.aead.Seal(out, nonce, pad(plaintext), aad(c, row, k.current.id))
}

// Open decrypts a value Seal made for the same column and row, under the current or
// the previous key.
func (k *Keys) Open(c Column, row Row, sealed []byte) ([]byte, error) {
	if len(sealed) < Overhead+PaddingBlock || sealed[0] != Format {
		return nil, fmt.Errorf("%w: %s is not a sealed value", ErrOpen, c)
	}
	var id [KeyIDSize]byte
	copy(id[:], sealed[1:])
	kk := &k.current
	if id != kk.id {
		if k.previous == nil || id != k.previous.id {
			return nil, fmt.Errorf("%w: %s was sealed under an unknown key", ErrOpen, c)
		}
		kk = k.previous
	}
	nonce := sealed[1+KeyIDSize : 1+KeyIDSize+chacha20poly1305.NonceSizeX]
	padded, err := kk.aead.Open(nil, nonce, sealed[1+KeyIDSize+len(nonce):], aad(c, row, id))
	if err != nil {
		return nil, fmt.Errorf("%w: %s does not belong to this row, or was altered", ErrOpen, c)
	}
	plain, err := unpad(padded)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrOpen, c, err)
	}
	return plain, nil
}

// Current reports whether a sealed value is under the current key (else reseal it).
func (k *Keys) Current(sealed []byte) bool {
	return len(sealed) > KeyIDSize && [KeyIDSize]byte(sealed[1:1+KeyIDSize]) == k.current.id
}

// SealString seals a string.
func (k *Keys) SealString(c Column, row Row, s string) []byte { return k.Seal(c, row, []byte(s)) }

// OpenString opens a string.
func (k *Keys) OpenString(c Column, row Row, sealed []byte) (string, error) {
	b, err := k.Open(c, row, sealed)
	return string(b), err
}

// SealOptional seals a string, or stores NULL for nil.
func (k *Keys) SealOptional(c Column, row Row, s *string) []byte {
	if s == nil {
		return nil
	}
	return k.SealString(c, row, *s)
}

// OpenOptional opens a nullable string column: NULL is nil.
func (k *Keys) OpenOptional(c Column, row Row, sealed []byte) (*string, error) {
	if sealed == nil {
		return nil, nil
	}
	s, err := k.OpenString(c, row, sealed)
	return &s, err
}

// OpenBytes opens a nullable bytes column: NULL is nil.
func (k *Keys) OpenBytes(c Column, row Row, sealed []byte) ([]byte, error) {
	if sealed == nil {
		return nil, nil
	}
	return k.Open(c, row, sealed)
}

// Hash is the blind index of an already normalised value: HMAC-SHA256 under the
// current DatabaseHMAC key.
func (k *Keys) Hash(value []byte) []byte {
	m := hmac.New(sha256.New, k.current.hmac)
	m.Write(value)
	return m.Sum(nil)
}

// HashString is Hash of a string.
func (k *Keys) HashString(s string) []byte { return k.Hash([]byte(s)) }

// HashOptional is the blind index of an optional value: NULL for nil.
func (k *Keys) HashOptional(s *string) []byte {
	if s == nil {
		return nil
	}
	return k.HashString(*s)
}

// NormaliseEmail is the form an address is hashed and stored in: surrounding
// whitespace trimmed, Unicode NFC, the whole address lower-cased, and NFC again, since
// lower-casing can leave a string that is not NFC (İ followed by a combining accent
// lowers to i, a dot above and the accent, which recompose differently). The second
// NFC makes it idempotent: NormaliseEmail(NormaliseEmail(s)) == NormaliseEmail(s), so
// a stored address hashes to the same index as the one it came from. No provider
// rules (Gmail's dots and plus tags): two spellings a provider treats as one stay two.
func NormaliseEmail(s string) string {
	return norm.NFC.String(strings.ToLower(norm.NFC.String(strings.TrimSpace(s))))
}

// LockKey turns a blind index into a key for pg_advisory_xact_lock.
func LockKey(hash []byte) int64 { return int64(binary.BigEndian.Uint64(hash[:8])) }

func pad(b []byte) []byte {
	n := PaddingBlock - len(b)%PaddingBlock
	out := make([]byte, len(b), len(b)+n)
	copy(out, b)
	for range n {
		out = append(out, byte(n))
	}
	return out
}

func unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%PaddingBlock != 0 {
		return nil, errors.New("bad padding length")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > PaddingBlock {
		return nil, errors.New("bad padding")
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("bad padding")
		}
	}
	return b[:len(b)-n], nil
}
