// Package e2ee implements the byte formats of docs/crypto.md.
//
// The server uses it only to check sizes, curve points and signatures; it
// never holds a practice key, a share key or a recovery secret. The phones
// implement the same formats, tested against testdata/vectors.json.
package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Labels, fixed by the format version.
const (
	LabelSeal        = "duongondro/v1/seal"
	LabelWrap        = "duongondro/v1/wrap"
	LabelWrapSig     = "duongondro/v1/wrap-sig"
	LabelEnrolAuth   = "duongondro/v1/enrol-auth"
	LabelSelfAuth    = "duongondro/v1/self-auth"
	LabelInviteAuth  = "duongondro/v1/invite-auth"
	LabelInvitePin   = "duongondro/v1/invite-pin"
	LabelRecovery    = "duongondro/v1/recovery"
	LabelRecoverySig = "duongondro/v1/recovery-sig"
	statementPrefix  = "duongondro/v1/"
	keySize          = 32
	padBlock         = 256
	NonceSize        = chacha20poly1305.NonceSize
	PublicKeySize    = 65
	SessionAADSize   = 36
	WrapAADSize      = 37
	WrappedBoxSize   = NonceSize + keySize + chacha20poly1305.Overhead
)

// WrapKind says what a wrap carries.
type WrapKind byte

const (
	KindPracticeKey  WrapKind = 1
	KindIdentitySeed WrapKind = 2
	KindShareKey     WrapKind = 3
)

// UUID is the raw 16 bytes of a UUID.
type UUID [16]byte

var (
	ErrOpen    = errors.New("e2ee: authentication failed")
	ErrPadding = errors.New("e2ee: bad padding")
	ErrSize    = errors.New("e2ee: wrong size")
)

// Derive is HKDF-SHA256 with a 32-byte output.
func Derive(ikm, salt []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, salt, info, keySize)
	if err != nil {
		panic(err) // only possible for absurd output lengths
	}
	return k
}

// SealKey derives seal_key from the practice key.
func SealKey(practiceKey []byte, user UUID) []byte {
	return Derive(practiceKey, user[:], LabelSeal)
}

// SessionAAD binds a sealed session to its id, user and key version.
func SessionAAD(session, user UUID, keyVersion uint32) []byte {
	aad := make([]byte, 0, SessionAADSize)
	aad = append(aad, session[:]...)
	aad = append(aad, user[:]...)
	return binary.BigEndian.AppendUint32(aad, keyVersion)
}

// Pad appends 0x80 and zero bytes up to the next multiple of 256.
func Pad(b []byte) []byte {
	n := len(b) + 1
	out := make([]byte, n+(padBlock-n%padBlock)%padBlock)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

// Unpad reverses Pad.
func Unpad(b []byte) ([]byte, error) {
	i := bytes.LastIndexFunc(b, func(r rune) bool { return r != 0 })
	if i < 0 || b[i] != 0x80 {
		return nil, ErrPadding
	}
	return b[:i], nil
}

func seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, ErrSize
	}
	out := append([]byte{}, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

func open(key, box, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(box) < NonceSize+aead.Overhead() {
		return nil, ErrSize
	}
	pt, err := aead.Open(nil, box[:NonceSize], box[NonceSize:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// SealSession pads and seals a session's JSON.
func SealSession(sealKey []byte, session, user UUID, keyVersion uint32, json, nonce []byte) ([]byte, error) {
	return seal(sealKey, nonce, Pad(json), SessionAAD(session, user, keyVersion))
}

// OpenSession opens and unpads a sealed session.
func OpenSession(sealKey []byte, session, user UUID, keyVersion uint32, sealed []byte) ([]byte, error) {
	pt, err := open(sealKey, sealed, SessionAAD(session, user, keyVersion))
	if err != nil {
		return nil, err
	}
	return Unpad(pt)
}

// WrapAAD binds a wrap to the user, key version, recipient device and kind.
func WrapAAD(user UUID, keyVersion uint32, device UUID, kind WrapKind) []byte {
	aad := make([]byte, 0, WrapAADSize)
	aad = append(aad, user[:]...)
	aad = binary.BigEndian.AppendUint32(aad, keyVersion)
	aad = append(aad, device[:]...)
	return append(aad, byte(kind))
}

func wrapKey(shared, epk, recipientPk []byte) []byte {
	salt := append(append([]byte{}, epk...), recipientPk...)
	return Derive(shared, salt, LabelWrap)
}

// Wrap seals a 32-byte secret to a recipient device key, using the given
// ephemeral key (always fresh in production; fixed only in test vectors).
func Wrap(recipient *ecdh.PublicKey, ephemeral *ecdh.PrivateKey, secret, aad, nonce []byte) (epk, box []byte, err error) {
	if len(secret) != keySize {
		return nil, nil, ErrSize
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, nil, err
	}
	epk = ephemeral.PublicKey().Bytes()
	box, err = seal(wrapKey(shared, epk, recipient.Bytes()), nonce, secret, aad)
	return epk, box, err
}

// Unwrap opens a wrap with the recipient's device key. Verify the wrap's
// authenticator first.
func Unwrap(recipient *ecdh.PrivateKey, epk, box, aad []byte) ([]byte, error) {
	if len(epk) != PublicKeySize || len(box) != WrappedBoxSize {
		return nil, ErrSize
	}
	pub, err := ParsePublicKey(epk)
	if err != nil {
		return nil, err
	}
	shared, err := recipient.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return open(wrapKey(shared, epk, recipient.PublicKey().Bytes()), box, aad)
}

// ParsePublicKey accepts only 65-byte uncompressed points on the glowie curve (NIST
// P-256); Go rejects compressed points, the point at infinity and points off the
// curve.
func ParsePublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrSize
	}
	pub, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("e2ee: invalid public key: %w", err)
	}
	return pub, nil
}

func authenticated(epk, box, aad, recipientPk []byte) []byte {
	var b []byte
	for _, p := range [][]byte{epk, box, aad, recipientPk} {
		b = append(b, p...)
	}
	return b
}

// WrapSignatureMessage is what the sender's identity key signs.
func WrapSignatureMessage(epk, box, aad, recipientPk []byte) []byte {
	return append([]byte(LabelWrapSig), authenticated(epk, box, aad, recipientPk)...)
}

// SignWrap signs a wrap with an identity key.
func SignWrap(identity ed25519.PrivateKey, epk, box, aad, recipientPk []byte) []byte {
	return ed25519.Sign(identity, WrapSignatureMessage(epk, box, aad, recipientPk))
}

// VerifyWrap checks a wrap signature.
func VerifyWrap(identity ed25519.PublicKey, epk, box, aad, recipientPk, sig []byte) bool {
	return len(identity) == ed25519.PublicKeySize &&
		ed25519.Verify(identity, WrapSignatureMessage(epk, box, aad, recipientPk), sig)
}

// EnrolTag authenticates a new device's first wrap with the QR secret.
func EnrolTag(qrSecret, epk, box, aad, recipientPk []byte) []byte {
	key := Derive(qrSecret, recipientPk, LabelEnrolAuth)
	return mac(key, authenticated(epk, box, aad, recipientPk))
}

// SelfTag authenticates a device's wrap to itself; selfShared is
// ECDH(d, d·G), which only the holder of d can compute.
func SelfTag(selfShared []byte, user UUID, epk, box, aad, recipientPk []byte) []byte {
	key := Derive(selfShared, user[:], LabelSelfAuth)
	return mac(key, authenticated(epk, box, aad, recipientPk))
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// EqualTag compares authenticators in constant time.
func EqualTag(a, b []byte) bool { return hmac.Equal(a, b) }

// StatementMessage is what an identity key signs for a statement.
func StatementMessage(typ string, payload []byte) []byte {
	return append([]byte(statementPrefix+typ+"\n"), payload...)
}

// SignStatement signs a statement's exact payload bytes.
func SignStatement(identity ed25519.PrivateKey, typ string, payload []byte) []byte {
	return ed25519.Sign(identity, StatementMessage(typ, payload))
}

// VerifyStatement checks a statement signature over the bytes received.
func VerifyStatement(identity ed25519.PublicKey, typ string, payload, sig []byte) bool {
	return len(identity) == ed25519.PublicKeySize &&
		ed25519.Verify(identity, StatementMessage(typ, payload), sig)
}

// InviteKeys derives the server's redemption key and the phones' pinning key.
func InviteKeys(secret []byte) (auth, pin []byte) {
	return Derive(secret, nil, LabelInviteAuth), Derive(secret, nil, LabelInvitePin)
}

// InviteMAC binds an invite to the inviter's identity key.
func InviteMAC(pin []byte, inviterIdentityPk ed25519.PublicKey) []byte {
	return mac(pin, inviterIdentityPk)
}

// RecoveryKey derives the key that seals recovery boxes.
func RecoveryKey(recoverySecret []byte, user UUID) []byte {
	return Derive(recoverySecret, user[:], LabelRecovery)
}

// RecoveryAAD binds a recovery box to its user and kind.
func RecoveryAAD(user UUID, kind WrapKind) []byte {
	return append(append([]byte{}, user[:]...), byte(kind))
}

// SealRecovery seals a secret under the recovery key.
func SealRecovery(recoveryKey []byte, user UUID, kind WrapKind, secret, nonce []byte) ([]byte, error) {
	return seal(recoveryKey, nonce, secret, RecoveryAAD(user, kind))
}

// RecoveryBoxMessage is what the identity key signs for a recovery box, so the
// server can refuse a box from a session that holds no key.
func RecoveryBoxMessage(user UUID, kind WrapKind, box []byte) []byte {
	msg := append([]byte(LabelRecoverySig), user[:]...)
	msg = append(msg, byte(kind))
	return append(msg, box...)
}

func SignRecoveryBox(identity ed25519.PrivateKey, user UUID, kind WrapKind, box []byte) []byte {
	return ed25519.Sign(identity, RecoveryBoxMessage(user, kind, box))
}

func VerifyRecoveryBox(identity ed25519.PublicKey, user UUID, kind WrapKind, box, sig []byte) bool {
	return len(identity) == ed25519.PublicKeySize && ed25519.Verify(identity, RecoveryBoxMessage(user, kind, box), sig)
}

// OpenRecovery opens a recovery box.
func OpenRecovery(recoveryKey []byte, user UUID, kind WrapKind, box []byte) ([]byte, error) {
	return open(recoveryKey, box, RecoveryAAD(user, kind))
}
