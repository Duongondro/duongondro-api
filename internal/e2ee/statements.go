package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// Bytes marshals as unpadded base64url.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := base64.RawURLEncoding.DecodeString(s)
	*b = v
	return err
}

// Statement payloads. Fields are declared in lexicographic key order, which is
// the order encoding/json writes them in, so Marshal yields the canonical form.

type Device struct {
	ID   string `json:"id"`
	PK   Bytes  `json:"pk"`
	Tier string `json:"tier"` // hardware, tee or software
}

type DeviceList struct {
	Devices  []Device `json:"devices"`
	IssuedAt int64    `json:"issuedAt"`
	User     string   `json:"user"`
	Version  int64    `json:"version"`
}

type Streak struct {
	Current  int    `json:"current"`
	Day      string `json:"day"`
	Deadline int64  `json:"deadline"`
	Longest  int    `json:"longest"`
	Practice string `json:"practice"`
	Seq      int64  `json:"seq"`
	User     string `json:"user"`
}

type Invite struct {
	ExpiresAt         int64  `json:"expiresAt"`
	InviteID          string `json:"inviteId"`
	Inviter           string `json:"inviter"`
	InviterIdentityPk Bytes  `json:"inviterIdentityPk"`
}

type Acceptance struct {
	InviteID          string `json:"inviteId"`
	Invitee           string `json:"invitee"`
	InviteeIdentityPk Bytes  `json:"inviteeIdentityPk"`
}

// Statement types as signed.
const (
	TypeDeviceList = "device-list"
	TypeStreak     = "streak"
	TypeInvite     = "invite"
	TypeAcceptance = "acceptance"
)

// Marshal encodes a payload in the canonical form: compact, keys in order,
// no HTML escaping.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
