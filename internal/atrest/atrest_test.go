package atrest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"uuid"

	"golang.org/x/crypto/chacha20poly1305"
)

// testBase is SECRET_KEY_BASE = the bytes 0x00 to 0x3f.
func testBase() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The vectors were computed with OpenSSL, not with this package:
//
//	openssl kdf -keylen 32 -kdfopt digest:SHA512 -kdfopt hexkey:000102…3f \
//	    -kdfopt info:ColumnLevelEncryption HKDF
//	printf 'ana@example.com' | openssl dgst -sha256 -mac HMAC -macopt hexkey:<DatabaseHMAC>
//
// homeosapiens-go's config.MustDeriveKey (HKDF-SHA512, no salt) gives the same keys
// for the same base, so the two projects' key handling stays one recipe.
func TestKeyDerivationVectors(t *testing.T) {
	cases := []struct {
		info string
		size int
		want string
	}{
		{infoColumns, 32, "8F:7F:B5:C3:5A:BF:2E:2D:E3:1F:C2:E3:BE:7B:2B:0D:9A:79:46:F1:34:76:9D:A7:D6:03:66:58:2E:BF:63:B3"},
		{infoHMAC, 32, "D6:4C:D5:12:EA:F4:90:B2:3A:13:85:DB:53:5C:2A:8E:CE:F4:2F:DB:83:6B:F2:49:65:BD:E1:6E:BE:94:47:CE"},
		{infoKeyID, 4, "E0:3C:B5:00"},
	}
	for _, c := range cases {
		got, err := DeriveKey(testBase(), c.info, c.size)
		if err != nil || !bytes.Equal(got, mustHex(t, c.want)) {
			t.Errorf("HKDF %s: %x, %v", c.info, got, err)
		}
	}
	k, err := New(testBase(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if id := k.KeyID(); hex.EncodeToString(id[:]) != "e03cb500" {
		t.Errorf("key id %x", id)
	}
	want := "f8cfb5e2cc9c826d87a5e349844ea52b40bb71adf6c9629ea26de0c0a8db2377"
	if got := hex.EncodeToString(k.HashString(NormaliseEmail("  Ana@Example.COM "))); got != want {
		t.Errorf("email hash %s, want %s", got, want)
	}
}

// A sealed value with a fixed nonce, pinned so the format cannot drift unnoticed, and
// opened here by hand from the documented layout (docs/at-rest.md).
func TestSealedFormat(t *testing.T) {
	k, _ := New(testBase(), nil)
	id := uuid.MustParse("0192f1d2-3c4b-7a5e-8f60-718293a4b5c6")
	nonce := bytes.Repeat([]byte{0x24}, chacha20poly1305.NonceSizeX)
	sealed := k.sealWithNonce(UsersDisplayName, IDRow(id), []byte("Ana"), nonce)
	const want = "01e03cb5002424242424242424242424242424242424242424242424247ad05a6378b6cc5f9476b50dd510f480fef3c36909604942c29c11693dbf9541bdd5deb2afbeef5843d794b2610b8ddc"
	if got := hex.EncodeToString(sealed); got != want {
		t.Errorf("sealed %s\nwant   %s", got, want)
	}
	if len(sealed) != Overhead+PaddingBlock {
		t.Fatalf("%d bytes, want %d", len(sealed), Overhead+PaddingBlock)
	}

	// By hand: the layout and the AAD as documented.
	key, _ := DeriveKey(testBase(), "ColumnLevelEncryption", 32)
	aead, _ := chacha20poly1305.NewX(key)
	var aad []byte
	aad = append(aad, "duongondro/at-rest/v1"...)
	aad = append(aad, 0, 5)
	aad = append(aad, "users"...)
	aad = append(aad, 0, 22)
	aad = append(aad, "display_name_encrypted"...)
	aad = append(aad, 0, 18, 0, 16)
	aad = append(aad, id[:]...)
	aad = append(aad, 1, 0xe0, 0x3c, 0xb5, 0x00)
	padded, err := aead.Open(nil, sealed[5:29], sealed[29:], aad)
	if err != nil {
		t.Fatalf("opening by hand: %v", err)
	}
	if !bytes.Equal(padded, append([]byte("Ana"), bytes.Repeat([]byte{29}, 29)...)) {
		t.Fatalf("padded plaintext %x", padded)
	}
}

func TestSealOpen(t *testing.T) {
	k, _ := New(testBase(), nil)
	a, b := uuid.NewV7(), uuid.NewV7()
	for _, plain := range []string{"", "Ana", strings.Repeat("x", 31), strings.Repeat("x", 32), strings.Repeat("ż", 100)} {
		s := k.SealString(UsersDisplayName, IDRow(a), plain)
		if (len(s)-Overhead)%PaddingBlock != 0 || len(s)-Overhead <= len(plain) {
			t.Errorf("%d bytes for %d: not padded to whole blocks", len(s), len(plain))
		}
		got, err := k.OpenString(UsersDisplayName, IDRow(a), s)
		if err != nil || got != plain {
			t.Errorf("round trip of %q: %q, %v", plain, got, err)
		}
	}
	if s1, s2 := k.SealString(UsersGender, IDRow(a), "female"), k.SealString(UsersGender, IDRow(a), "female"); bytes.Equal(s1, s2) {
		t.Error("two seals of one value are equal: the nonce is not random")
	}

	// The AAD binds the value to its table, column and row.
	s := k.SealString(UsersDisplayName, IDRow(a), "Ana")
	for name, open := range map[string]func() error{
		"another row":    func() error { _, err := k.Open(UsersDisplayName, IDRow(b), s); return err },
		"another column": func() error { _, err := k.Open(UsersUsername, IDRow(a), s); return err },
		"another table": func() error {
			_, err := k.Open(Column{"webauthn_sessions", "display_name_encrypted"}, IDRow(a), s)
			return err
		},
		"tampered": func() error {
			bad := bytes.Clone(s)
			bad[len(bad)-1] ^= 1
			_, err := k.Open(UsersDisplayName, IDRow(a), bad)
			return err
		},
		"truncated": func() error { _, err := k.Open(UsersDisplayName, IDRow(a), s[:40]); return err },
	} {
		if err := open(); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	// Parts are length-prefixed, so they cannot be shifted between key columns.
	if bytes.Equal(RowOf([]byte("ab"), []byte("c")), RowOf([]byte("a"), []byte("bc"))) {
		t.Error("RowOf is ambiguous")
	}
}

func TestRotation(t *testing.T) {
	oldBase, newBase := testBase(), bytes.Repeat([]byte{7}, 64)
	old, _ := New(oldBase, nil)
	id := uuid.NewV7()
	s := old.SealString(PushTokensToken, IDRow(id), "token")

	rotating, err := New(newBase, oldBase)
	if err != nil {
		t.Fatal(err)
	}
	if !rotating.Rotating() || rotating.Current(s) {
		t.Fatal("a value under the previous key counts as current")
	}
	if got, err := rotating.OpenString(PushTokensToken, IDRow(id), s); err != nil || got != "token" {
		t.Fatalf("the previous key no longer opens its values: %q %v", got, err)
	}
	if !rotating.Current(rotating.SealString(PushTokensToken, IDRow(id), "token")) {
		t.Fatal("a new seal is not under the current key")
	}
	if bytes.Equal(old.HashString("x"), rotating.HashString("x")) {
		t.Fatal("the blind index key did not rotate with the base")
	}
	after, _ := New(newBase, nil)
	if _, err := after.Open(PushTokensToken, IDRow(id), s); !errors.Is(err, ErrOpen) {
		t.Fatalf("without the previous key: %v", err)
	}
	if _, err := New(oldBase, oldBase); err == nil {
		t.Fatal("the previous key may equal the current one")
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := FromEnv(env(nil), nil); err == nil || !strings.Contains(err.Error(), "SECRET_KEY_BASE is not set") {
		t.Fatalf("no key and no default: %v", err)
	}
	if k, err := FromEnv(env(nil), testBase()); err != nil || k.KeyID() != [4]byte{0xe0, 0x3c, 0xb5, 0x00} {
		t.Fatalf("the DEV default: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(testBase())
	if k, err := FromEnv(env(map[string]string{"SECRET_KEY_BASE": " " + b64 + "\n"}), nil); err != nil || k.Rotating() {
		t.Fatalf("a key: %v", err)
	}
	if _, err := FromEnv(env(map[string]string{"SECRET_KEY_BASE": base64.StdEncoding.EncodeToString(make([]byte, 16))}), nil); err == nil {
		t.Fatal("a 16-byte key was accepted")
	}
	if _, err := FromEnv(env(map[string]string{"SECRET_KEY_BASE": "not base64!"}), nil); err == nil {
		t.Fatal("a key that is not base64 was accepted")
	}
	k, err := FromEnv(env(map[string]string{"SECRET_KEY_BASE": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64)),
		"SECRET_KEY_BASE_PREVIOUS": b64}), nil)
	if err != nil || !k.Rotating() {
		t.Fatalf("a rotation: %v", err)
	}
}

func TestNormaliseEmail(t *testing.T) {
	for in, want := range map[string]string{
		"  Ana@Example.COM\t": "ana@example.com",
		"Ana.B+Tag@gmail.com": "ana.b+tag@gmail.com", // no provider rules
		"Zoé@example.com":    "zoé@example.com",     // NFC: e + combining acute is é
		"ZOÉ@EXAMPLE.COM":     "zoé@example.com",
		"ana@example.com":     "ana@example.com",
	} {
		if got := NormaliseEmail(in); got != want {
			t.Errorf("NormaliseEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPadding(t *testing.T) {
	for n := 0; n <= 70; n++ {
		p := pad(bytes.Repeat([]byte{'a'}, n))
		if len(p)%PaddingBlock != 0 || len(p) <= n {
			t.Fatalf("pad(%d) is %d bytes", n, len(p))
		}
		if u, err := unpad(p); err != nil || len(u) != n {
			t.Fatalf("unpad(pad(%d)): %d %v", n, len(u), err)
		}
	}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{0}, 32), append(bytes.Repeat([]byte{1}, 31), 33), append(bytes.Repeat([]byte{1}, 30), 2, 3)} {
		if _, err := unpad(bad); err == nil {
			t.Errorf("unpad(%x) accepted bad padding", bad)
		}
	}
}
