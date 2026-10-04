package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
)

type testDevice struct {
	ID   string
	Key  *ecdh.PrivateKey
	Tier string
}

func newDevice(t *testing.T) testDevice {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{ID: ids.NewV7().String(), Key: k, Tier: "hardware"}
}

func (d testDevice) pk() []byte { return d.Key.PublicKey().Bytes() }

func (e *env) registerDevice(u *user, d testDevice) {
	e.t.Helper()
	e.want(e.call("POST", "/api/devices", u.Token, map[string]any{"id": d.ID, "publicKey": e2ee.Bytes(d.pk()), "tier": d.Tier}), http.StatusCreated, "")
}

// signedList signs a device-list payload with u's identity key.
func signedList(t *testing.T, u *user, version int64, devs ...testDevice) map[string]any {
	l := e2ee.DeviceList{IssuedAt: time.Now().UnixMilli(), User: u.ID, Version: version}
	for _, d := range devs {
		l.Devices = append(l.Devices, e2ee.Device{ID: d.ID, PK: d.pk(), Tier: d.Tier})
	}
	payload, err := e2ee.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"payload": e2ee.Bytes(payload), "signature": e2ee.Bytes(e2ee.SignStatement(u.Identity, e2ee.TypeDeviceList, payload))}
}

func TestDevices(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	d := newDevice(t)
	body := map[string]any{"id": d.ID, "publicKey": e2ee.Bytes(d.pk()), "tier": "hardware"}
	e.want(e.call("POST", "/api/devices", u.Token, body), http.StatusCreated, "")
	e.want(e.call("POST", "/api/devices", u.Token, body), http.StatusOK, "") // idempotent

	// Same id with another tier or key, or the key under another id.
	e.want(e.call("POST", "/api/devices", u.Token, map[string]any{"id": d.ID, "publicKey": e2ee.Bytes(d.pk()), "tier": "software"}), http.StatusConflict, "device_conflict")
	e.want(e.call("POST", "/api/devices", u.Token, map[string]any{"id": ids.NewV7().String(), "publicKey": e2ee.Bytes(d.pk()), "tier": "hardware"}), http.StatusConflict, "device_conflict")
	other := e.newUser("Dolma")
	e.want(e.call("POST", "/api/devices", other.Token, body), http.StatusConflict, "device_conflict")

	// Not a point on the curve; wrong size; unknown tier.
	bad := append([]byte{4}, make([]byte, 64)...)
	e.want(e.call("POST", "/api/devices", u.Token, map[string]any{"id": ids.NewV7().String(), "publicKey": e2ee.Bytes(bad), "tier": "hardware"}), http.StatusBadRequest, "bad_request")
	e.want(e.call("POST", "/api/devices", u.Token, map[string]any{"id": ids.NewV7().String(), "publicKey": e2ee.Bytes(d.pk()[:64]), "tier": "hardware"}), http.StatusBadRequest, "bad_request")
	e.want(e.call("POST", "/api/devices", u.Token, map[string]any{"id": ids.NewV7().String(), "publicKey": e2ee.Bytes(newDevice(t).pk()), "tier": "enclave"}), http.StatusBadRequest, "bad_request")

	var list []deviceJSON
	r := e.call("GET", "/api/devices", u.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &list)
	if len(list) != 1 || list[0].ID != d.ID || list[0].Tier != "hardware" {
		t.Fatalf("devices %s", r.Body)
	}

	e.want(e.call("DELETE", "/api/devices/"+d.ID, other.Token, nil), http.StatusNotFound, "not_found")
	e.want(e.call("DELETE", "/api/devices/nope", u.Token, nil), http.StatusBadRequest, "bad_request")
	// Deleting the device bound to this session also ends the session.
	e.want(e.call("DELETE", "/api/devices/"+d.ID, u.Token, nil), http.StatusNoContent, "")
	e.want(e.call("GET", "/api/devices", u.Token, nil), http.StatusUnauthorized, "unauthorized")
}

func TestDeviceList(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	d1, d2 := newDevice(t), newDevice(t)
	e.registerDevice(u, d1)

	// Listing an unregistered device is refused.
	e.want(e.call("PUT", "/api/device-list", u.Token, signedList(t, u, 1, d1, d2)), http.StatusUnprocessableEntity, "unknown_device")
	d2.Tier = "software"
	e.registerDevice(u, d2)
	r := e.call("PUT", "/api/device-list", u.Token, signedList(t, u, 1, d1, d2))
	e.want(r, http.StatusOK, "")

	// Versions only go up.
	r = e.call("PUT", "/api/device-list", u.Token, signedList(t, u, 1, d1))
	e.want(r, http.StatusConflict, "stale_version")
	var ve versionError
	r.json(t, &ve)
	if ve.CurrentVersion != 1 {
		t.Fatalf("current %d", ve.CurrentVersion)
	}
	e.want(e.call("PUT", "/api/device-list", u.Token, signedList(t, u, 2, d1)), http.StatusOK, "")

	// A tier that differs from the registration is refused.
	d1.Tier = "tee"
	e.want(e.call("PUT", "/api/device-list", u.Token, signedList(t, u, 3, d1)), http.StatusUnprocessableEntity, "unknown_device")
	d1.Tier = "hardware"

	// Signed by another key, or naming another user.
	mallory := e.newUser("Mallory")
	forged := signedList(t, mallory, 9, d1)
	e.want(e.call("PUT", "/api/device-list", u.Token, forged), http.StatusUnprocessableEntity, "bad_signature")
	wrong := signedList(t, &user{ID: mallory.ID, Identity: u.Identity}, 9, d1)
	e.want(e.call("PUT", "/api/device-list", u.Token, wrong), http.StatusUnprocessableEntity, "wrong_user")
	// A valid signature over bytes that are not a device list.
	junk := []byte(`{"devices":[],"issuedAt":1,"user":"x","version":1,"extra":1}`)
	e.want(e.call("PUT", "/api/device-list", u.Token, map[string]any{"payload": e2ee.Bytes(junk), "signature": e2ee.Bytes(e2ee.SignStatement(u.Identity, e2ee.TypeDeviceList, junk))}), http.StatusBadRequest, "bad_request")
	// Signed as another statement type.
	payload := signedList(t, u, 5, d1)["payload"].(e2ee.Bytes)
	e.want(e.call("PUT", "/api/device-list", u.Token, map[string]any{"payload": payload, "signature": e2ee.Bytes(e2ee.SignStatement(u.Identity, e2ee.TypeStreak, payload))}), http.StatusUnprocessableEntity, "bad_signature")

	// Fetch: own and a friend's, never a stranger's or across a block.
	var got deviceListJSON
	r = e.call("GET", "/api/users/"+u.ID+"/device-list", u.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &got)
	if got.Version != 2 || !ed25519.Verify(u.Identity.Public().(ed25519.PublicKey), e2ee.StatementMessage(e2ee.TypeDeviceList, got.Payload), got.Signature) {
		t.Fatalf("list %s", r.Body)
	}
	friend := e.newUser("Dolma")
	e.want(e.call("GET", "/api/users/"+u.ID+"/device-list", friend.Token, nil), http.StatusNotFound, "not_found")
	e.befriend(u, friend)
	e.want(e.call("GET", "/api/users/"+u.ID+"/device-list", friend.Token, nil), http.StatusOK, "")
	e.block(u, friend)
	e.want(e.call("GET", "/api/users/"+u.ID+"/device-list", friend.Token, nil), http.StatusNotFound, "not_found")

	// No pinned identity: nothing can be signed.
	bare := e.newUser("Bare")
	if _, err := e.store.Pool().Exec(t.Context(), `UPDATE users SET identity_pk = NULL WHERE id = $1`, bare.ID); err != nil {
		t.Fatal(err)
	}
	e.want(e.call("PUT", "/api/device-list", bare.Token, signedList(t, bare, 1, d1)), http.StatusConflict, "no_identity")
}

func (e *env) befriend(a, b *user) {
	e.t.Helper()
	if err := e.store.Befriend(e.t.Context(), a.ID, b.ID); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) block(blocker, blocked *user) {
	e.t.Helper()
	if _, err := e.store.Pool().Exec(e.t.Context(), `INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2)`, blocker.ID, blocked.ID); err != nil {
		e.t.Fatal(err)
	}
}

// makeWrap wraps a random secret from sender to (owner, device).
func makeWrap(t *testing.T, sender, owner *user, d testDevice, kind e2ee.WrapKind, keyVersion uint32) map[string]any {
	uid, _ := ids.ParseUUID(owner.ID)
	did, _ := ids.ParseUUID(d.ID)
	aad := e2ee.WrapAAD(e2ee.UUID(uid), keyVersion, e2ee.UUID(did), kind)
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	secret := make([]byte, 32)
	nonce := make([]byte, 12)
	_, _ = rand.Read(secret)
	_, _ = rand.Read(nonce)
	epk, box, err := e2ee.Wrap(d.Key.PublicKey(), eph, secret, aad, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"user": owner.ID, "keyVersion": keyVersion, "recipientDevice": d.ID, "kind": int(kind),
		"epk": e2ee.Bytes(epk), "box": e2ee.Bytes(box),
		"authenticatorKind": "signature",
		"authenticator":     e2ee.Bytes(e2ee.SignWrap(sender.Identity, epk, box, aad, d.pk())),
	}
}

func TestWraps(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	d := newDevice(t)
	e.registerDevice(u, d)

	e.want(e.call("PUT", "/api/wraps", u.Token, makeWrap(t, u, u, d, e2ee.KindPracticeKey, 1)), http.StatusNoContent, "")
	// Replacing the same wrap is fine.
	e.want(e.call("PUT", "/api/wraps", u.Token, makeWrap(t, u, u, d, e2ee.KindPracticeKey, 1)), http.StatusNoContent, "")

	// Enrolment and self tags are stored as received: the server cannot
	// check an HMAC keyed by a secret it never sees.
	enrol := makeWrap(t, u, u, d, e2ee.KindIdentitySeed, 1)
	enrol["authenticatorKind"] = "enrol"
	enrol["authenticator"] = e2ee.Bytes(make([]byte, 32))
	e.want(e.call("PUT", "/api/wraps", u.Token, enrol), http.StatusNoContent, "")

	// A bad signature is refused; sizes are checked.
	forged := makeWrap(t, e.newUser("Mallory"), u, d, e2ee.KindPracticeKey, 2)
	e.want(e.call("PUT", "/api/wraps", u.Token, forged), http.StatusUnprocessableEntity, "bad_signature")
	for k, v := range map[string]any{
		"box":           e2ee.Bytes(make([]byte, 59)),
		"epk":           e2ee.Bytes(append([]byte{4}, make([]byte, 64)...)),
		"authenticator": e2ee.Bytes(make([]byte, 32)),
		"kind":          4,
		"keyVersion":    0,
		"sender":        u.ID,
	} {
		w := makeWrap(t, u, u, d, e2ee.KindPracticeKey, 1)
		w[k] = v
		e.want(e.call("PUT", "/api/wraps", u.Token, w), http.StatusBadRequest, "bad_request")
	}
	// Recipient device must belong to the user in the AAD.
	stranger := newDevice(t)
	e.want(e.call("PUT", "/api/wraps", u.Token, makeWrap(t, u, u, stranger, e2ee.KindPracticeKey, 1)), http.StatusUnprocessableEntity, "unknown_device")

	// Friends may wrap share keys only, signed, and not across a block.
	f := e.newUser("Dolma")
	e.want(e.call("PUT", "/api/wraps", f.Token, makeWrap(t, f, u, d, e2ee.KindShareKey, 1)), http.StatusForbidden, "forbidden")
	e.befriend(u, f)
	e.want(e.call("PUT", "/api/wraps", f.Token, makeWrap(t, f, u, d, e2ee.KindShareKey, 1)), http.StatusNoContent, "")
	e.want(e.call("PUT", "/api/wraps", f.Token, makeWrap(t, f, u, d, e2ee.KindPracticeKey, 1)), http.StatusForbidden, "forbidden")

	var ws []wrapJSON
	r := e.call("GET", "/api/wraps?device="+d.ID, u.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &ws)
	if len(ws) != 3 {
		t.Fatalf("wraps %s", r.Body)
	}
	senders := map[string]int{}
	for _, w := range ws {
		senders[w.Sender]++
		if len(w.Box) != 60 || len(w.EPK) != 65 {
			t.Fatalf("wrap %v", w)
		}
	}
	if senders[u.ID] != 2 || senders[f.ID] != 1 {
		t.Fatalf("senders %v", senders)
	}
	r = e.call("GET", "/api/wraps?device="+d.ID+"&kind=3", u.Token, nil)
	ws = nil
	r.json(t, &ws)
	if len(ws) != 1 || ws[0].Sender != f.ID {
		t.Fatalf("kind 3 %s", r.Body)
	}
	e.want(e.call("GET", "/api/wraps?device="+d.ID, f.Token, nil), http.StatusNotFound, "not_found")
	e.want(e.call("GET", "/api/wraps?device=x", u.Token, nil), http.StatusBadRequest, "bad_request")
	e.want(e.call("GET", "/api/wraps?device="+d.ID+"&kind=7", u.Token, nil), http.StatusBadRequest, "bad_request")

	e.block(f, u)
	e.want(e.call("PUT", "/api/wraps", f.Token, makeWrap(t, f, u, d, e2ee.KindShareKey, 2)), http.StatusForbidden, "forbidden")
}

func TestRecoveryBoxes(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	box := make([]byte, 60)
	box[0] = 1
	e.want(e.call("PUT", "/api/recovery-boxes/1", u.Token, map[string]any{"box": e2ee.Bytes(box)}), http.StatusNoContent, "")
	box[0] = 2
	e.want(e.call("PUT", "/api/recovery-boxes/1", u.Token, map[string]any{"box": e2ee.Bytes(box)}), http.StatusNoContent, "")
	e.want(e.call("PUT", "/api/recovery-boxes/2", u.Token, map[string]any{"box": e2ee.Bytes(box)}), http.StatusNoContent, "")
	e.want(e.call("PUT", "/api/recovery-boxes/3", u.Token, map[string]any{"box": e2ee.Bytes(box)}), http.StatusBadRequest, "bad_request")
	e.want(e.call("PUT", "/api/recovery-boxes/1", u.Token, map[string]any{"box": e2ee.Bytes(box[:59])}), http.StatusBadRequest, "bad_request")
	var got []struct {
		Kind int        `json:"kind"`
		Box  e2ee.Bytes `json:"box"`
	}
	r := e.call("GET", "/api/recovery-boxes", u.Token, nil)
	e.want(r, http.StatusOK, "")
	r.json(t, &got)
	if len(got) != 2 || got[0].Kind != 1 || got[0].Box[0] != 2 {
		t.Fatalf("boxes %s", r.Body)
	}
	r = e.call("GET", "/api/recovery-boxes", e.newUser("Dolma").Token, nil)
	if string(r.Body) != "[]\n" {
		t.Fatalf("other user's boxes %s", r.Body)
	}
}

func TestKeyVersion(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("Tenzin")
	r := e.call("PUT", "/api/me/key-version", u.Token, map[string]any{"keyVersion": 2})
	e.want(r, http.StatusOK, "")
	var me accountJSON
	r.json(t, &me)
	if me.KeyVersion != 2 {
		t.Fatalf("me %s", r.Body)
	}
	r = e.call("PUT", "/api/me/key-version", u.Token, map[string]any{"keyVersion": 4})
	e.want(r, http.StatusConflict, "key_version_conflict")
	var kv keyVersionError
	r.json(t, &kv)
	if kv.CurrentKeyVersion != 2 {
		t.Fatalf("current %d", kv.CurrentKeyVersion)
	}
	e.want(e.call("PUT", "/api/me/key-version", u.Token, map[string]any{"keyVersion": 1}), http.StatusBadRequest, "bad_request")
}
