package bitwarden

import "time"

// Every string documented as encrypted holds an EncString in wire form; the
// server never sees those values in the clear.

// CipherType is the kind of vault item.
type CipherType int

// Item kinds of the protocol.
const (
	CipherLogin      CipherType = 1
	CipherSecureNote CipherType = 2
	CipherCard       CipherType = 3
	CipherIdentity   CipherType = 4
	CipherSSHKey     CipherType = 5
)

// FieldType is the kind of a custom field.
type FieldType int

// Custom field kinds.
const (
	FieldText    FieldType = 0
	FieldHidden  FieldType = 1
	FieldBoolean FieldType = 2
	FieldLinked  FieldType = 3
)

// MemberStatus is the state of an organization membership.
type MemberStatus int

// Membership states.
const (
	MemberRevoked   MemberStatus = -1
	MemberInvited   MemberStatus = 0
	MemberAccepted  MemberStatus = 1
	MemberConfirmed MemberStatus = 2
)

// MemberType is the role of an organization member.
type MemberType int

// Member roles.
const (
	MemberOwner   MemberType = 0
	MemberAdmin   MemberType = 1
	MemberUser    MemberType = 2
	MemberManager MemberType = 3
	MemberCustom  MemberType = 4
)

// Profile is the account as the sync response reports it.
type Profile struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	Name          string         `json:"name"`
	Key           string         `json:"key"`        // user key, encrypted with the stretched master key
	PrivateKey    string         `json:"privateKey"` // encrypted with the user key
	Organizations []Organization `json:"organizations"`
}

// Organization is one membership of the account.
type Organization struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Key     string       `json:"key"` // organization key, RSA-wrapped for this account
	Type    MemberType   `json:"type"`
	Status  MemberStatus `json:"status"`
	Enabled bool         `json:"enabled"`
}

// Collection is a group of organization items.
type Collection struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"` // encrypted with the organization key
	ExternalID     string `json:"externalId,omitempty"`
	ReadOnly       bool   `json:"readOnly"`
	HidePasswords  bool   `json:"hidePasswords"`
	Manage         bool   `json:"manage"`
}

// URI is one address of a login.
type URI struct {
	URI         *string `json:"uri"`
	URIChecksum *string `json:"uriChecksum,omitempty"`
	Match       *int    `json:"match"`
}

// Login holds the credentials of a login item.
type Login struct {
	Username             *string `json:"username"`
	Password             *string `json:"password"`
	TOTP                 *string `json:"totp"`
	URIs                 []URI   `json:"uris"`
	PasswordRevisionDate *string `json:"passwordRevisionDate,omitempty"`
	AutofillOnPageLoad   *bool   `json:"autofillOnPageLoad,omitempty"`
	// Fido2Credentials is carried through untouched so an update never drops
	// passkeys a human added in another client.
	Fido2Credentials []map[string]any `json:"fido2Credentials,omitempty"`
}

// SecureNote marks a note item; its only field is the note subtype.
type SecureNote struct {
	Type int `json:"type"`
}

// SSHKey holds an SSH key pair item.
type SSHKey struct {
	PrivateKey     *string `json:"privateKey"`
	PublicKey      *string `json:"publicKey"`
	KeyFingerprint *string `json:"keyFingerprint"`
}

// Card holds a payment card; every value is encrypted.
type Card struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

// Identity holds personal data; every value is encrypted.
type Identity struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

// Field is a custom field.
type Field struct {
	Name     *string   `json:"name"`
	Value    *string   `json:"value"`
	Type     FieldType `json:"type"`
	LinkedID *int      `json:"linkedId"`
}

// PasswordHistory is one previous password of a login.
type PasswordHistory struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

// Attachment is a file stored with an item.
type Attachment struct {
	ID       string `json:"id"`
	URL      string `json:"url,omitempty"`
	FileName string `json:"fileName"` // encrypted
	Key      string `json:"key"`      // attachment key, encrypted with the item key
	Size     string `json:"size"`
	SizeName string `json:"sizeName,omitempty"`
}

// Cipher is a vault item as the server stores it.
type Cipher struct {
	ID              string            `json:"id,omitempty"`
	OrganizationID  *string           `json:"organizationId"`
	FolderID        *string           `json:"folderId"`
	Type            CipherType        `json:"type"`
	Name            string            `json:"name"`
	Notes           *string           `json:"notes"`
	Key             *string           `json:"key"` // per-item key; when set, fields are encrypted with it
	Favorite        bool              `json:"favorite"`
	Reprompt        int               `json:"reprompt"`
	Login           *Login            `json:"login"`
	SecureNote      *SecureNote       `json:"secureNote"`
	Card            *Card             `json:"card"`
	Identity        *Identity         `json:"identity"`
	SSHKey          *SSHKey           `json:"sshKey"`
	Fields          []Field           `json:"fields"`
	PasswordHistory []PasswordHistory `json:"passwordHistory"`
	Attachments     []Attachment      `json:"attachments,omitempty"`
	CollectionIDs   []string          `json:"collectionIds,omitempty"`
	RevisionDate    string            `json:"revisionDate,omitempty"`
	CreationDate    string            `json:"creationDate,omitempty"`
	DeletedDate     *string           `json:"deletedDate,omitempty"`
	Edit            bool              `json:"edit,omitempty"`
	ViewPassword    bool              `json:"viewPassword,omitempty"`
	// LastKnownRevisionDate makes an update fail instead of overwriting a
	// change made elsewhere since the item was read.
	LastKnownRevisionDate string `json:"lastKnownRevisionDate,omitempty"`
}

// SyncResponse is everything the account can see.
type SyncResponse struct {
	Profile     Profile      `json:"profile"`
	Collections []Collection `json:"collections"`
	Ciphers     []Cipher     `json:"ciphers"`
	Sends       []Send       `json:"sends"`
}

// SendText is the content of a text Send.
type SendText struct {
	Text   string `json:"text"`
	Hidden bool   `json:"hidden"`
}

// Send is a share link. Its content is encrypted with a key derived from a seed
// that only the link's URL fragment carries.
type Send struct {
	ID             string    `json:"id,omitempty"`
	AccessID       string    `json:"accessId,omitempty"`
	Type           int       `json:"type"`
	Name           string    `json:"name"`
	Notes          *string   `json:"notes"`
	Key            string    `json:"key"` // the seed, encrypted with the user key
	Text           *SendText `json:"text"`
	MaxAccessCount *int      `json:"maxAccessCount"`
	AccessCount    int       `json:"accessCount,omitempty"`
	ExpirationDate *string   `json:"expirationDate"`
	DeletionDate   string    `json:"deletionDate"`
	Disabled       bool      `json:"disabled"`
	HideEmail      bool      `json:"hideEmail"`
	Password       *string   `json:"password"`
}

// CollectionAccess grants one member or group access to one collection.
type CollectionAccess struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

// Member is an organization membership as the admin API reports it.
type Member struct {
	ID          string             `json:"id"`
	UserID      string             `json:"userId"`
	Email       string             `json:"email"`
	Name        string             `json:"name"`
	Status      MemberStatus       `json:"status"`
	Type        MemberType         `json:"type"`
	AccessAll   bool               `json:"accessAll"`
	Collections []CollectionAccess `json:"collections"`
	Groups      []string           `json:"groups"`
}

// CollectionDetails is a collection with the members assigned to it.
type CollectionDetails struct {
	Collection
	Users  []CollectionAccess `json:"users"`
	Groups []CollectionAccess `json:"groups"`
}

// Event is one entry of the organization event log.
type Event struct {
	Type         int     `json:"type"`
	ActingUserID *string `json:"actingUserId"`
	UserID       *string `json:"userId"`
	CipherID     *string `json:"cipherId"`
	CollectionID *string `json:"collectionId"`
	MemberID     *string `json:"organizationUserId"`
	Date         string  `json:"date"`
	IPAddress    *string `json:"ipAddress"`
	Device       *int    `json:"device"`
}

// FormatTime renders a timestamp the way the server writes them.
func FormatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
