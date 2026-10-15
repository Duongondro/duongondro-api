package atrest

import (
	"time"
	"uuid"

	"github.com/Duongondro/duongondro-api/internal/db"
)

// The rows with sealed columns, opened. Each Open method takes what a sqlc query
// returns, error included, so a read is one line:
//
//	user, err := keys.User(q.GetUser(ctx, id))
//
// The JSON names are the plain columns', for the GDPR export.

type User struct {
	ID                uuid.UUID `json:"id"`
	IdentityPublicKey []byte    `json:"identityPublicKey"`
	KeyVersion        int32     `json:"keyVersion"`
	CreatedAt         time.Time `json:"createdAt"`
	DisplayName       string    `json:"displayName"`
	Username          *string   `json:"username"`
	Gender            *string   `json:"gender"`
}

func (k *Keys) User(r db.User, err error) (User, error) {
	if err != nil {
		return User{}, err
	}
	row := IDRow(r.ID)
	u := User{ID: r.ID, KeyVersion: r.KeyVersion, CreatedAt: r.CreatedAt}
	if u.IdentityPublicKey, err = k.OpenBytes(UsersIdentityPublicKey, row, r.IdentityPublicKeyEncrypted); err != nil {
		return User{}, err
	}
	if name, err := k.OpenOptional(UsersDisplayName, row, r.DisplayNameEncrypted); err != nil {
		return User{}, err
	} else if name != nil {
		u.DisplayName = *name
	}
	if u.Username, err = k.OpenOptional(UsersUsername, row, r.UsernameEncrypted); err != nil {
		return User{}, err
	}
	if u.Gender, err = k.OpenOptional(UsersGender, row, r.GenderEncrypted); err != nil {
		return User{}, err
	}
	return u, nil
}

// SealDisplayName seals a display name for users.display_name_encrypted; an empty
// one is NULL.
func (k *Keys) SealDisplayName(userID uuid.UUID, name string) []byte {
	if name == "" {
		return nil
	}
	return k.SealString(UsersDisplayName, IDRow(userID), name)
}

// Friend is a row of ListFriends.
type Friend struct {
	ID                uuid.UUID `json:"id"`
	DisplayName       string    `json:"displayName"`
	Gender            *string   `json:"gender"`
	IdentityPublicKey []byte    `json:"identityPublicKey"`
	CreatedAt         time.Time `json:"createdAt"`
	NotifyDone        bool      `json:"notifyDone"`
}

func (k *Keys) Friends(rows []db.ListFriendsRow, err error) ([]Friend, error) {
	return each(rows, err, func(r db.ListFriendsRow) (Friend, error) {
		u, err := k.User(db.User{ID: r.ID, DisplayNameEncrypted: r.DisplayNameEncrypted, GenderEncrypted: r.GenderEncrypted,
			IdentityPublicKeyEncrypted: r.IdentityPublicKeyEncrypted}, nil)
		return Friend{ID: r.ID, DisplayName: u.DisplayName, Gender: u.Gender, IdentityPublicKey: u.IdentityPublicKey,
			CreatedAt: r.CreatedAt, NotifyDone: r.NotifyDone}, err
	})
}

type Device struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"userId"`
	PublicKey []byte    `json:"publicKey"`
	Tier      string    `json:"tier"`
	CreatedAt time.Time `json:"createdAt"`
}

func (k *Keys) Device(r db.Device, err error) (Device, error) {
	if err != nil {
		return Device{}, err
	}
	key, err := k.Open(DevicesPublicKey, IDRow(r.ID), r.PublicKeyEncrypted)
	return Device{ID: r.ID, UserID: r.UserID, PublicKey: key, Tier: r.Tier, CreatedAt: r.CreatedAt}, err
}

func (k *Keys) Devices(rows []db.Device, err error) ([]Device, error) {
	return each(rows, err, func(r db.Device) (Device, error) { return k.Device(r, nil) })
}

// PracticeKeyHolders opens the devices' keys of a PracticeKeyHolders read.
func (k *Keys) PracticeKeyHolders(rows []db.PracticeKeyHoldersRow, err error) ([]Device, error) {
	return each(rows, err, func(r db.PracticeKeyHoldersRow) (Device, error) {
		key, err := k.Open(DevicesPublicKey, IDRow(r.ID), r.PublicKeyEncrypted)
		return Device{ID: r.ID, PublicKey: key}, err
	})
}

type DeviceList struct {
	UserID    uuid.UUID `json:"userId"`
	Version   int64     `json:"version"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (k *Keys) DeviceList(r db.DeviceList, err error) (DeviceList, error) {
	if err != nil {
		return DeviceList{}, err
	}
	payload, err := k.Open(DeviceListsPayload, IDRow(r.UserID), r.PayloadEncrypted)
	return DeviceList{UserID: r.UserID, Version: r.Version, Payload: payload, Signature: r.Signature, UpdatedAt: r.UpdatedAt}, err
}

// UserKey is the signed user-key statement (docs/crypto.md, Passkey unlock).
type UserKey struct {
	UserID    uuid.UUID `json:"userId"`
	ID        uuid.UUID `json:"id"`
	Version   int64     `json:"version"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (k *Keys) UserKey(r db.UserKey, err error) (UserKey, error) {
	if err != nil {
		return UserKey{}, err
	}
	payload, err := k.Open(UserKeysPayload, IDRow(r.UserID), r.PayloadEncrypted)
	return UserKey{UserID: r.UserID, ID: r.ID, Version: r.Version, Payload: payload, Signature: r.Signature, UpdatedAt: r.UpdatedAt}, err
}

type Invite struct {
	ID        string     `json:"id"`
	InviterID uuid.UUID  `json:"inviterId"`
	AuthHash  []byte     `json:"authHash"`
	Payload   []byte     `json:"payload"`
	Signature []byte     `json:"signature"`
	Mac       []byte     `json:"mac"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt"`
	CreatedAt time.Time  `json:"createdAt"`
}

// InviteRow is the Row of an invite.
func InviteRow(id string) Row { return RowOf([]byte(id)) }

func (k *Keys) Invite(r db.Invite, err error) (Invite, error) {
	if err != nil {
		return Invite{}, err
	}
	payload, err := k.Open(InvitesPayload, InviteRow(r.ID), r.PayloadEncrypted)
	return Invite{ID: r.ID, InviterID: r.InviterID, AuthHash: r.AuthHash, Payload: payload, Signature: r.Signature, Mac: r.Mac,
		ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}, err
}

func (k *Keys) Invites(rows []db.Invite, err error) ([]Invite, error) {
	return each(rows, err, func(r db.Invite) (Invite, error) { return k.Invite(r, nil) })
}

type InviteRedemption struct {
	InviteID  string    `json:"inviteId"`
	InviteeID uuid.UUID `json:"inviteeId"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"`
	CreatedAt time.Time `json:"createdAt"`
}

// RedemptionRow is the Row of an invite redemption.
func RedemptionRow(inviteID string, invitee uuid.UUID) Row {
	return RowOf([]byte(inviteID), invitee[:])
}

func (k *Keys) InviteRedemptions(rows []db.InviteRedemption, err error) ([]InviteRedemption, error) {
	return each(rows, err, func(r db.InviteRedemption) (InviteRedemption, error) {
		payload, err := k.Open(InviteRedemptionsPayload, RedemptionRow(r.InviteID, r.InviteeID), r.PayloadEncrypted)
		return InviteRedemption{InviteID: r.InviteID, InviteeID: r.InviteeID, Payload: payload, Signature: r.Signature,
			CreatedAt: r.CreatedAt}, err
	})
}

// Report is a report as the export shows it.
type Report struct {
	ID         uuid.UUID  `json:"id"`
	ReportedID *uuid.UUID `json:"reportedId"`
	Reason     string     `json:"reason"`
	CreatedAt  time.Time  `json:"createdAt"`
}

func (k *Keys) Reports(rows []db.ExportReportsRow, err error) ([]Report, error) {
	return each(rows, err, func(r db.ExportReportsRow) (Report, error) {
		reason, err := k.OpenString(ReportsReason, IDRow(r.ID), r.ReasonEncrypted)
		return Report{ID: r.ID, ReportedID: r.ReportedID, Reason: reason, CreatedAt: r.CreatedAt}, err
	})
}

type Streak struct {
	UserID        uuid.UUID `json:"userId"`
	Practice      string    `json:"practice"`
	Seq           int64     `json:"seq"`
	Payload       []byte    `json:"payload"`
	Signature     []byte    `json:"signature"`
	DeadlineAt    time.Time `json:"deadlineAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	AtRiskSentSeq int64     `json:"atRiskSentSeq"`
	// PracticeHash is the stored key, for updating the row; a blind index, so it
	// stays out of the export.
	PracticeHash []byte `json:"-"`
}

// StreakRow is the Row of a streak: its user and the practice's hash.
func StreakRow(userID uuid.UUID, practiceHash []byte) Row { return RowOf(userID[:], practiceHash) }

func (k *Keys) Streak(r db.Streak, err error) (Streak, error) {
	if err != nil {
		return Streak{}, err
	}
	row := StreakRow(r.UserID, r.PracticeHash)
	s := Streak{UserID: r.UserID, Seq: r.Seq, Signature: r.Signature, DeadlineAt: r.DeadlineAt, UpdatedAt: r.UpdatedAt,
		AtRiskSentSeq: r.AtRiskSentSeq, PracticeHash: r.PracticeHash}
	if s.Practice, err = k.OpenString(StreaksPractice, row, r.PracticeEncrypted); err != nil {
		return Streak{}, err
	}
	s.Payload, err = k.Open(StreaksPayload, row, r.PayloadEncrypted)
	return s, err
}

func (k *Keys) Streaks(rows []db.Streak, err error) ([]Streak, error) {
	return each(rows, err, func(r db.Streak) (Streak, error) { return k.Streak(r, nil) })
}

type Credential struct {
	ID         []byte
	UserID     uuid.UUID
	Data       []byte
	Name       *string // given by the person; nil: the app names it after its password manager
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func (k *Keys) Credentials(rows []db.Credential, err error) ([]Credential, error) {
	return each(rows, err, func(r db.Credential) (Credential, error) {
		data, err := k.Open(CredentialsData, RowOf(r.ID), r.DataEncrypted)
		if err != nil {
			return Credential{}, err
		}
		name, err := k.OpenOptional(CredentialsName, RowOf(r.ID), r.NameEncrypted)
		return Credential{ID: r.ID, UserID: r.UserID, Data: data, Name: name, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt}, err
	})
}

// ExportCredential is a passkey as the export lists it: no key material.
type ExportCredential struct {
	ID         []byte     `json:"id"`
	Name       *string    `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

func (k *Keys) ExportCredentials(rows []db.ExportCredentialsRow, err error) ([]ExportCredential, error) {
	return each(rows, err, func(r db.ExportCredentialsRow) (ExportCredential, error) {
		name, err := k.OpenOptional(CredentialsName, RowOf(r.ID), r.NameEncrypted)
		return ExportCredential{ID: r.ID, Name: name, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt}, err
	})
}

// Ceremony is a passkey ceremony in flight (webauthn_sessions).
type Ceremony struct {
	ID          uuid.UUID
	Data        []byte
	UserID      *uuid.UUID
	InviteID    *string
	AdmissionID *uuid.UUID
	CreatedAt   time.Time
	Username    *string
	DisplayName *string
	Gender      *string
}

func (k *Keys) Ceremony(r db.WebauthnSession, err error) (Ceremony, error) {
	if err != nil {
		return Ceremony{}, err
	}
	row := IDRow(r.ID)
	c := Ceremony{ID: r.ID, Data: r.Data, UserID: r.UserID, InviteID: r.InviteID, AdmissionID: r.AdmissionID, CreatedAt: r.CreatedAt}
	if c.Username, err = k.OpenOptional(WebauthnSessionsUsername, row, r.UsernameEncrypted); err != nil {
		return Ceremony{}, err
	}
	if c.DisplayName, err = k.OpenOptional(WebauthnSessionsDisplayName, row, r.DisplayNameEncrypted); err != nil {
		return Ceremony{}, err
	}
	c.Gender, err = k.OpenOptional(WebauthnSessionsGender, row, r.GenderEncrypted)
	return c, err
}

// Identity is a sign-in identity (auth_identities).
type Identity struct {
	Provider     string
	Subject      string
	SubjectHash  []byte
	UserID       uuid.UUID
	Email        *string
	RefreshToken *string
	CreatedAt    time.Time
}

// IdentityRow is the Row of an identity: its provider and the subject's hash.
func IdentityRow(provider string, subjectHash []byte) Row {
	return RowOf([]byte(provider), subjectHash)
}

func (k *Keys) Identity(r db.AuthIdentity, err error) (Identity, error) {
	if err != nil {
		return Identity{}, err
	}
	row := IdentityRow(r.Provider, r.SubjectHash)
	i := Identity{Provider: r.Provider, SubjectHash: r.SubjectHash, UserID: r.UserID, CreatedAt: r.CreatedAt}
	if i.Subject, err = k.OpenString(AuthIdentitiesSubject, row, r.SubjectEncrypted); err != nil {
		return Identity{}, err
	}
	if i.Email, err = k.OpenOptional(AuthIdentitiesEmail, row, r.EmailEncrypted); err != nil {
		return Identity{}, err
	}
	i.RefreshToken, err = k.OpenOptional(AuthIdentitiesRefreshToken, row, r.RefreshTokenEncrypted)
	return i, err
}

func (k *Keys) Identities(rows []db.AuthIdentity, err error) ([]Identity, error) {
	return each(rows, err, func(r db.AuthIdentity) (Identity, error) { return k.Identity(r, nil) })
}

// ExportIdentity is an identity as the export shows it: no refresh token.
type ExportIdentity struct {
	Provider  string    `json:"provider"`
	Subject   string    `json:"subject"`
	Email     *string   `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

func (k *Keys) ExportIdentities(rows []db.ExportIdentitiesRow, err error) ([]ExportIdentity, error) {
	return each(rows, err, func(r db.ExportIdentitiesRow) (ExportIdentity, error) {
		row := IdentityRow(r.Provider, r.SubjectHash)
		subject, err := k.OpenString(AuthIdentitiesSubject, row, r.SubjectEncrypted)
		if err != nil {
			return ExportIdentity{}, err
		}
		email, err := k.OpenOptional(AuthIdentitiesEmail, row, r.EmailEncrypted)
		return ExportIdentity{Provider: r.Provider, Subject: subject, Email: email, CreatedAt: r.CreatedAt}, err
	})
}

type MagicLink struct {
	TokenHash   []byte
	Email       string
	InviteID    *string
	AdmissionID *uuid.UUID
	CodeHash    []byte
	WrongCodes  int16
	CodeDeadAt  *time.Time
	CreatedAt   time.Time
}

func (k *Keys) MagicLink(r db.MagicLink, err error) (MagicLink, error) {
	if err != nil {
		return MagicLink{}, err
	}
	email, err := k.OpenString(MagicLinksEmail, RowOf(r.TokenHash), r.EmailEncrypted)
	return MagicLink{TokenHash: r.TokenHash, Email: email, InviteID: r.InviteID, AdmissionID: r.AdmissionID,
		CodeHash: r.CodeHash, WrongCodes: r.WrongCodes, CodeDeadAt: r.CodeDeadAt, CreatedAt: r.CreatedAt}, err
}

// ExportMagicLink is an unused link as the export shows it: no hashes.
type ExportMagicLink struct {
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

func (k *Keys) ExportMagicLinks(rows []db.ExportMagicLinksRow, err error) ([]ExportMagicLink, error) {
	return each(rows, err, func(r db.ExportMagicLinksRow) (ExportMagicLink, error) {
		email, err := k.OpenString(MagicLinksEmail, RowOf(r.TokenHash), r.EmailEncrypted)
		return ExportMagicLink{Email: email, CreatedAt: r.CreatedAt}, err
	})
}

type PushToken struct {
	DeviceID  uuid.UUID
	Platform  string
	Token     string
	TokenHash []byte
	UpdatedAt time.Time
}

func (k *Keys) PushTokens(rows []db.PushToken, err error) ([]PushToken, error) {
	return each(rows, err, func(r db.PushToken) (PushToken, error) {
		token, err := k.OpenString(PushTokensToken, IDRow(r.DeviceID), r.TokenEncrypted)
		return PushToken{DeviceID: r.DeviceID, Platform: r.Platform, Token: token, TokenHash: r.TokenHash, UpdatedAt: r.UpdatedAt}, err
	})
}

func each[R, T any](rows []R, err error, open func(R) (T, error)) ([]T, error) {
	if err != nil {
		return nil, err
	}
	out := make([]T, len(rows))
	for i, r := range rows {
		if out[i], err = open(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}
