package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Duongondro/duongondro-api/internal/e2ee"
	"github.com/Duongondro/duongondro-api/internal/ids"
	"github.com/Duongondro/duongondro-api/internal/store"
)

const maxListedDevices = 32

func validTier(t string) bool { return t == "hardware" || t == "tee" || t == "software" }

// pathUUID parses a UUID path value into canonical form, answering 400 on
// failure.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	u, ok := ids.CanonicalUUID(r.PathValue(name))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
	}
	return u, ok
}

type deviceJSON struct {
	ID        string     `json:"id"`
	PublicKey e2ee.Bytes `json:"publicKey"`
	Tier      string     `json:"tier"`
	CreatedAt int64      `json:"createdAt"`
}

func deviceOut(d store.Device) deviceJSON {
	return deviceJSON{ID: d.ID, PublicKey: d.PublicKey, Tier: d.Tier, CreatedAt: d.CreatedAt.UnixMilli()}
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.store.ListDevices(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]deviceJSON, 0, len(ds))
	for _, d := range ds {
		out = append(out, deviceOut(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string     `json:"id"`
		PublicKey e2ee.Bytes `json:"publicKey"`
		Tier      string     `json:"tier"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, ok := ids.CanonicalUUID(req.ID)
	if !ok || !validTier(req.Tier) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if _, err := e2ee.ParsePublicKey(req.PublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	d, created, err := s.store.RegisterDevice(r.Context(), a.UserID, a.tokenHash, store.Device{ID: id, PublicKey: req.PublicKey, Tier: req.Tier})
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, apiError{Error: "device_conflict", Message: "The id or the key is already registered differently."})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, deviceOut(d))
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "deviceId")
	if !ok {
		return
	}
	err := s.store.DeleteDevice(r.Context(), caller(r).UserID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type signedJSON struct {
	Payload   e2ee.Bytes `json:"payload"`
	Signature e2ee.Bytes `json:"signature"`
}

// strictUnmarshal parses a signed payload, refusing unknown keys and
// trailing data. It runs only after the signature has been checked.
func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// sameUser compares a payload's user field with an id, ignoring case.
func sameUser(payloadUser, id string) bool {
	a, err1 := ids.ParseUUID(payloadUser)
	b, err2 := ids.ParseUUID(id)
	return err1 == nil && err2 == nil && a == b
}

func (s *Server) unprocessable(w http.ResponseWriter, code, msg string) {
	writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: code, Message: msg})
}

func noIdentity(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, apiError{Error: "no_identity", Message: "No identity key is pinned for this account."})
}

// identityOf returns the caller's pinned identity key, or nil.
func (s *Server) identityOf(w http.ResponseWriter, r *http.Request, userID string) (ed25519.PublicKey, bool) {
	u, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	if len(u.IdentityPK) != ed25519.PublicKeySize {
		noIdentity(w)
		return nil, false
	}
	return ed25519.PublicKey(u.IdentityPK), true
}

func validSignature(sig []byte) bool { return len(sig) == ed25519.SignatureSize }

func (s *Server) publishDeviceList(w http.ResponseWriter, r *http.Request) {
	var req signedJSON
	if !decode(w, r, &req) {
		return
	}
	if len(req.Payload) < 2 || len(req.Payload) > 16384 || !validSignature(req.Signature) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	identity, ok := s.identityOf(w, r, a.UserID)
	if !ok {
		return
	}
	// Verify over the exact bytes received, then parse.
	if !e2ee.VerifyStatement(identity, e2ee.TypeDeviceList, req.Payload, req.Signature) {
		s.unprocessable(w, "bad_signature", "The signature does not verify with the pinned identity key.")
		return
	}
	var list e2ee.DeviceList
	if err := strictUnmarshal(req.Payload, &list); err != nil || list.Version < 1 || len(list.Devices) == 0 || len(list.Devices) > maxListedDevices {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !sameUser(list.User, a.UserID) {
		s.unprocessable(w, "wrong_user", "The payload names another user.")
		return
	}
	seen := map[string]bool{}
	devices := make([]store.ListedDevice, 0, len(list.Devices))
	for _, d := range list.Devices {
		id, ok := ids.CanonicalUUID(d.ID)
		if !ok || seen[id] || !validTier(d.Tier) {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		if _, err := e2ee.ParsePublicKey(d.PK); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		seen[id] = true
		devices = append(devices, store.ListedDevice{ID: id, PublicKey: d.PK, Tier: d.Tier})
	}
	stored := store.DeviceList{UserID: a.UserID, Version: list.Version, Payload: req.Payload, Signature: req.Signature, IdentityPK: identity}
	current, err := s.store.PublishDeviceList(r.Context(), stored, devices)
	switch {
	case errors.Is(err, store.ErrStale):
		writeJSON(w, http.StatusConflict, versionError{Error: "stale_version", CurrentVersion: current})
	case errors.Is(err, store.ErrUnknownDevice):
		s.unprocessable(w, "unknown_device", "A listed device is not registered to this account with that key and tier.")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, http.StatusOK, deviceListOut(stored))
	}
}

type deviceListJSON struct {
	User       string     `json:"user"`
	Version    int64      `json:"version"`
	Payload    e2ee.Bytes `json:"payload"`
	Signature  e2ee.Bytes `json:"signature"`
	IdentityPK e2ee.Bytes `json:"identityPk"`
}

func deviceListOut(l store.DeviceList) deviceListJSON {
	return deviceListJSON{User: l.UserID, Version: l.Version, Payload: l.Payload, Signature: l.Signature, IdentityPK: l.IdentityPK}
}

func (s *Server) getDeviceList(w http.ResponseWriter, r *http.Request) {
	owner, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	l, err := s.store.GetDeviceList(r.Context(), caller(r).UserID, owner)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, deviceListOut(l))
}

type wrapJSON struct {
	User              string     `json:"user"`
	KeyVersion        int32      `json:"keyVersion"`
	RecipientDevice   string     `json:"recipientDevice"`
	Kind              int16      `json:"kind"`
	EPK               e2ee.Bytes `json:"epk"`
	Box               e2ee.Bytes `json:"box"`
	AuthenticatorKind string     `json:"authenticatorKind"`
	Authenticator     e2ee.Bytes `json:"authenticator"`
	Sender            string     `json:"sender,omitempty"`
	CreatedAt         int64      `json:"createdAt,omitempty"`
}

func (s *Server) putWrap(w http.ResponseWriter, r *http.Request) {
	var req wrapJSON
	if !decode(w, r, &req) {
		return
	}
	user, ok1 := ids.CanonicalUUID(req.User)
	device, ok2 := ids.CanonicalUUID(req.RecipientDevice)
	authLen := map[string]int{"signature": 64, "enrol": 32, "self": 32}[req.AuthenticatorKind]
	if !ok1 || !ok2 || req.Sender != "" || req.CreatedAt != 0 || req.KeyVersion < 1 || req.Kind < 1 || req.Kind > 3 ||
		len(req.Box) != 60 || authLen == 0 || len(req.Authenticator) != authLen {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if _, err := e2ee.ParsePublicKey(req.EPK); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	if user != a.UserID {
		// Only a share key (kind 3) may be wrapped to someone else, and only
		// to a friend with no block either way; a friend always signs it.
		ok, err := s.store.Connected(r.Context(), a.UserID, user)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if req.Kind != 3 || !ok || req.AuthenticatorKind != "signature" {
			writeJSON(w, http.StatusForbidden, apiError{Error: "forbidden", Message: "Not allowed to wrap this kind to this user."})
			return
		}
	}
	recipientPk, err := s.store.DevicePublicKey(r.Context(), user, device)
	if errors.Is(err, store.ErrNotFound) {
		s.unprocessable(w, "unknown_device", "The recipient device is not registered to this user.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A signature authenticator can be checked against the sender's pinned
	// identity key; enrolment and self tags are HMACs the server cannot
	// verify, so they are stored as received and only recipients check them.
	if req.AuthenticatorKind == "signature" {
		identity, ok := s.identityOf(w, r, a.UserID)
		if !ok {
			return
		}
		uid, _ := ids.ParseUUID(user)
		did, _ := ids.ParseUUID(device)
		aad := e2ee.WrapAAD(e2ee.UUID(uid), uint32(req.KeyVersion), e2ee.UUID(did), e2ee.WrapKind(req.Kind))
		if !e2ee.VerifyWrap(identity, req.EPK, req.Box, aad, recipientPk, req.Authenticator) {
			s.unprocessable(w, "bad_signature", "The wrap signature does not verify with the sender's identity key.")
			return
		}
	}
	err = s.store.PutWrap(r.Context(), store.Wrap{
		UserID: user, KeyVersion: req.KeyVersion, RecipientDevice: device, Kind: req.Kind, SenderID: a.UserID,
		EPK: req.EPK, Box: req.Box, AuthenticatorKind: req.AuthenticatorKind, Authenticator: req.Authenticator,
	})
	if errors.Is(err, store.ErrUnknownDevice) {
		s.unprocessable(w, "unknown_device", "The recipient device is not registered to this user.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listWraps(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	device, ok := ids.CanonicalUUID(q.Get("device"))
	var kind int16
	if k := q.Get("kind"); k != "" {
		n, err := strconv.Atoi(k)
		if err != nil || n < 1 || n > 3 {
			ok = false
		}
		kind = int16(n)
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ws, err := s.store.ListWraps(r.Context(), caller(r).UserID, device, kind)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]wrapJSON, 0, len(ws))
	for _, x := range ws {
		out = append(out, wrapJSON{
			User: x.UserID, KeyVersion: x.KeyVersion, RecipientDevice: x.RecipientDevice, Kind: x.Kind,
			EPK: x.EPK, Box: x.Box, AuthenticatorKind: x.AuthenticatorKind, Authenticator: x.Authenticator,
			Sender: x.SenderID, CreatedAt: x.CreatedAt.UnixMilli(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putRecoveryBox(w http.ResponseWriter, r *http.Request) {
	kind, err := strconv.Atoi(r.PathValue("kind"))
	var req struct {
		Box e2ee.Bytes `json:"box"`
	}
	if err != nil || kind < 1 || kind > 2 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Box) != 60 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := s.store.PutRecoveryBox(r.Context(), caller(r).UserID, int16(kind), req.Box); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRecoveryBoxes(w http.ResponseWriter, r *http.Request) {
	bs, err := s.store.ListRecoveryBoxes(r.Context(), caller(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type boxJSON struct {
		Kind      int16      `json:"kind"`
		Box       e2ee.Bytes `json:"box"`
		UpdatedAt int64      `json:"updatedAt"`
	}
	out := make([]boxJSON, 0, len(bs))
	for _, b := range bs {
		out = append(out, boxJSON{Kind: b.Kind, Box: b.Box, UpdatedAt: b.UpdatedAt.UnixMilli()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setKeyVersion(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyVersion int32 `json:"keyVersion"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.KeyVersion < 2 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	a := caller(r)
	current, err := s.store.SetKeyVersion(r.Context(), a.UserID, req.KeyVersion)
	if errors.Is(err, store.ErrStale) {
		writeJSON(w, http.StatusConflict, keyVersionError{Error: "key_version_conflict", CurrentKeyVersion: current})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getMe(w, r)
}
