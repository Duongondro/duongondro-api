package atrest

// The sealed columns. A column's name is part of every value's AAD: renaming one
// means resealing it.
var (
	UsersIdentityPublicKey = Column{"users", "identity_public_key_encrypted"}
	UsersDisplayName       = Column{"users", "display_name_encrypted"}
	UsersUsername          = Column{"users", "username_encrypted"}
	UsersGender            = Column{"users", "gender_encrypted"}

	DevicesPublicKey = Column{"devices", "public_key_encrypted"}

	DeviceListsPayload       = Column{"device_lists", "payload_encrypted"}
	InvitesPayload           = Column{"invites", "payload_encrypted"}
	InviteRedemptionsPayload = Column{"invite_redemptions", "payload_encrypted"}

	ReportsReason = Column{"reports", "reason_encrypted"}

	StreaksPractice = Column{"streaks", "practice_encrypted"}
	StreaksPayload  = Column{"streaks", "payload_encrypted"}

	CredentialsData = Column{"credentials", "data_encrypted"}

	WebauthnSessionsUsername    = Column{"webauthn_sessions", "username_encrypted"}
	WebauthnSessionsDisplayName = Column{"webauthn_sessions", "display_name_encrypted"}
	WebauthnSessionsGender      = Column{"webauthn_sessions", "gender_encrypted"}

	AuthIdentitiesSubject      = Column{"auth_identities", "subject_encrypted"}
	AuthIdentitiesEmail        = Column{"auth_identities", "email_encrypted"}
	AuthIdentitiesRefreshToken = Column{"auth_identities", "refresh_token_encrypted"}

	MagicLinksEmail = Column{"magic_links", "email_encrypted"}

	PushTokensToken = Column{"push_tokens", "token_encrypted"}
)

// Normalisation of a value before it is hashed.
type Normalisation int

const (
	// Exact hashes the value as stored.
	Exact Normalisation = iota
	// Email hashes NormaliseEmail of the value (it is stored normalised too).
	Email
)

// Index is a blind index: the hash of the plaintext of a sealed column.
type Index struct {
	Column Column // the hash column, e.g. users.username_hash
	Of     Column // the sealed column it indexes
	Norm   Normalisation
}

// Table describes how a table's sealed values are bound to their rows, for reseal
// and for the tests that check every column is classified.
type Table struct {
	Name string
	// Key lists the primary-key columns whose values make the Row, in order. A
	// uuid column contributes its 16 bytes, text its UTF-8, bytea its bytes.
	Key     []string
	Sealed  []Column
	Indexes []Index
}

// Tables lists every table with sealed columns.
var Tables = []Table{
	{Name: "users", Key: []string{"id"},
		Sealed:  []Column{UsersIdentityPublicKey, UsersDisplayName, UsersUsername, UsersGender},
		Indexes: []Index{{Column{"users", "username_hash"}, UsersUsername, Exact}}},
	{Name: "devices", Key: []string{"id"},
		Sealed:  []Column{DevicesPublicKey},
		Indexes: []Index{{Column{"devices", "public_key_hash"}, DevicesPublicKey, Exact}}},
	{Name: "device_lists", Key: []string{"user_id"}, Sealed: []Column{DeviceListsPayload}},
	{Name: "invites", Key: []string{"id"}, Sealed: []Column{InvitesPayload}},
	{Name: "invite_redemptions", Key: []string{"invite_id", "invitee_id"}, Sealed: []Column{InviteRedemptionsPayload}},
	{Name: "reports", Key: []string{"id"}, Sealed: []Column{ReportsReason}},
	// The row includes the practice's hash, which a rotation changes: reseal opens
	// under the stored hash and seals under the new one.
	{Name: "streaks", Key: []string{"user_id", "practice_hash"},
		Sealed:  []Column{StreaksPractice, StreaksPayload},
		Indexes: []Index{{Column{"streaks", "practice_hash"}, StreaksPractice, Exact}}},
	{Name: "credentials", Key: []string{"id"}, Sealed: []Column{CredentialsData}},
	{Name: "webauthn_sessions", Key: []string{"id"},
		Sealed: []Column{WebauthnSessionsUsername, WebauthnSessionsDisplayName, WebauthnSessionsGender}},
	{Name: "auth_identities", Key: []string{"provider", "subject_hash"},
		Sealed: []Column{AuthIdentitiesSubject, AuthIdentitiesEmail, AuthIdentitiesRefreshToken},
		// Apple and Google subjects are opaque; an e-mail subject is the normalised
		// address, already stored normalised, so hashing it exactly is the same.
		Indexes: []Index{
			{Column{"auth_identities", "subject_hash"}, AuthIdentitiesSubject, Exact},
			{Column{"auth_identities", "email_hash"}, AuthIdentitiesEmail, Email},
		}},
	{Name: "magic_links", Key: []string{"token_hash"},
		Sealed:  []Column{MagicLinksEmail},
		Indexes: []Index{{Column{"magic_links", "email_hash"}, MagicLinksEmail, Email}}},
	{Name: "push_tokens", Key: []string{"device_id"},
		Sealed:  []Column{PushTokensToken},
		Indexes: []Index{{Column{"push_tokens", "token_hash"}, PushTokensToken, Exact}}},
}
