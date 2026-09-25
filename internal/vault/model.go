package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// ItemType names a kind of item the way tools spell it.
type ItemType string

// Item kinds.
const (
	TypeLogin    ItemType = "login"
	TypeNote     ItemType = "note"
	TypeCard     ItemType = "card"
	TypeIdentity ItemType = "identity"
	TypeSSHKey   ItemType = "ssh_key"
)

// ErrUnknownType is returned for an item kind this service does not know.
var ErrUnknownType = errors.New("unknown item type")

var typeCodes = map[ItemType]bitwarden.CipherType{
	TypeLogin:    bitwarden.CipherLogin,
	TypeNote:     bitwarden.CipherSecureNote,
	TypeCard:     bitwarden.CipherCard,
	TypeIdentity: bitwarden.CipherIdentity,
	TypeSSHKey:   bitwarden.CipherSSHKey,
}

// ParseItemType validates a tool-supplied kind.
func ParseItemType(s string) (ItemType, error) {
	t := ItemType(s)
	if _, ok := typeCodes[t]; !ok {
		return "", fmt.Errorf("%w %q: want login, note, card, identity or ssh_key", ErrUnknownType, s)
	}
	return t, nil
}

func typeName(code bitwarden.CipherType) ItemType {
	for name, c := range typeCodes {
		if c == code {
			return name
		}
	}
	return ItemType("type_" + strconv.Itoa(int(code)))
}

// FieldKind is the kind of a custom field, as tools spell it.
type FieldKind string

// Custom field kinds. Hidden fields are secret; text and boolean fields are
// metadata and may be shown.
const (
	FieldText    FieldKind = "text"
	FieldHidden  FieldKind = "hidden"
	FieldBoolean FieldKind = "boolean"
	FieldLinked  FieldKind = "linked"
)

var fieldCodes = map[FieldKind]bitwarden.FieldType{
	FieldText:    bitwarden.FieldText,
	FieldHidden:  bitwarden.FieldHidden,
	FieldBoolean: bitwarden.FieldBoolean,
	FieldLinked:  bitwarden.FieldLinked,
}

func fieldKind(code bitwarden.FieldType) FieldKind {
	for name, c := range fieldCodes {
		if c == code {
			return name
		}
	}
	return FieldText
}

// URI is one address of a login.
type URI struct {
	URI   string
	Match *int
}

// Field is a custom field.
type Field struct {
	Name     string
	Value    string
	Kind     FieldKind
	LinkedID *int
}

// SSHKey is the key pair of an SSH key item.
type SSHKey struct {
	Private     string
	Public      string
	Fingerprint string
}

// PasswordChange is one previous password.
type PasswordChange struct {
	Password string
	Changed  time.Time
}

// Attachment is a file stored with an item.
type Attachment struct {
	ID       string
	FileName string
	Size     int64
	key      keys.SymmetricKey
}

// Item is a decrypted vault item. It never leaves the process as a whole:
// tools project it into what the caller may see.
type Item struct {
	ID             string
	OrganizationID string
	CollectionIDs  []string
	FolderID       *string
	Type           ItemType
	Name           string
	Notes          string
	Favorite       bool
	Reprompt       int

	Username string
	Password string
	TOTP     string
	URIs     []URI

	Fields          []Field
	SSH             *SSHKey
	Card            map[string]string
	Identity        map[string]string
	PasswordHistory []PasswordChange
	Attachments     []Attachment

	Created  time.Time
	Revised  time.Time
	Deleted  *time.Time
	Editable bool
	// Viewable is false when the account's access hides passwords: the
	// server then expects clients not to show secret values.
	Viewable bool

	// revision is the server's revision stamp, sent back on update so a
	// concurrent change elsewhere is refused instead of overwritten.
	revision string
	// key is the key the item's fields are encrypted with.
	key keys.SymmetricKey
	// wrappedKey is the per-item key as stored, when the item has one.
	wrappedKey *string
	// fido2 is carried through untouched, so an update never drops a passkey.
	fido2 []map[string]any
	// passwordRevised is the server's stamp of the last password change.
	passwordRevised *string
	// autofill is a browser-extension setting, carried through untouched.
	autofill *bool
}

// Field returns the custom field with the given name.
func (it *Item) Field(name string) (Field, bool) {
	for _, f := range it.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// cardFields and identityFields pair the tool-facing names with the protocol
// structs, so both directions of the conversion share one table.
func cardFields(c *bitwarden.Card) []namedField {
	return []namedField{
		{"cardholder_name", &c.CardholderName},
		{"brand", &c.Brand},
		{"number", &c.Number},
		{"exp_month", &c.ExpMonth},
		{"exp_year", &c.ExpYear},
		{"code", &c.Code},
	}
}

func identityFields(i *bitwarden.Identity) []namedField {
	return []namedField{
		{"title", &i.Title},
		{"first_name", &i.FirstName},
		{"middle_name", &i.MiddleName},
		{"last_name", &i.LastName},
		{"address1", &i.Address1},
		{"address2", &i.Address2},
		{"address3", &i.Address3},
		{"city", &i.City},
		{"state", &i.State},
		{"postal_code", &i.PostalCode},
		{"country", &i.Country},
		{"company", &i.Company},
		{"email", &i.Email},
		{"phone", &i.Phone},
		{"ssn", &i.SSN},
		{"username", &i.Username},
		{"passport_number", &i.PassportNumber},
		{"license_number", &i.LicenseNumber},
	}
}

// IsSecretCardField and IsSecretIdentityField name the parts of those items
// that are secret values rather than metadata.
func IsSecretCardField(name string) bool { return name == "number" || name == "code" }

// IsSecretIdentityField is IsSecretCardField for identity items.
func IsSecretIdentityField(name string) bool {
	return name == "ssn" || name == "passport_number" || name == "license_number"
}

type namedField struct {
	name string
	ptr  **string
}

// decoder decrypts the fields of one item with one key, remembering the first
// failure so a whole item is either readable or reported as damaged.
type decoder struct {
	key keys.SymmetricKey
	err error
}

func (d *decoder) str(s string) string {
	if s == "" || d.err != nil {
		return ""
	}
	out, err := d.key.DecryptString(s)
	if err != nil {
		d.err = err
	}
	return out
}

func (d *decoder) opt(s *string) string {
	if s == nil {
		return ""
	}
	return d.str(*s)
}

// decryptCipher turns a stored item into its readable form. ownerKey is the
// key of the item's owner: the organization key or the user key.
func decryptCipher(c bitwarden.Cipher, ownerKey keys.SymmetricKey) (Item, error) {
	key := ownerKey
	if c.Key != nil && *c.Key != "" {
		k, err := ownerKey.DecryptKey(*c.Key)
		if err != nil {
			return Item{}, fmt.Errorf("unwrap item key: %w", err)
		}
		key = k
	}
	d := &decoder{key: key}
	it := Item{
		ID:            c.ID,
		CollectionIDs: slices.Clone(c.CollectionIDs),
		FolderID:      c.FolderID,
		Type:          typeName(c.Type),
		Name:          d.str(c.Name),
		Notes:         d.opt(c.Notes),
		Favorite:      c.Favorite,
		Reprompt:      c.Reprompt,
		Editable:      c.Edit,
		Viewable:      c.ViewPassword || c.OrganizationID == nil,
		revision:      c.RevisionDate,
		key:           key,
		wrappedKey:    c.Key,
	}
	if c.OrganizationID != nil {
		it.OrganizationID = *c.OrganizationID
	}
	it.Created, _ = parseTime(c.CreationDate) // an unparsable stamp only loses a display field
	it.Revised, _ = parseTime(c.RevisionDate)
	if c.DeletedDate != nil {
		if t, err := parseTime(*c.DeletedDate); err == nil {
			it.Deleted = &t
		}
	}

	if l := c.Login; l != nil {
		it.Username = d.opt(l.Username)
		it.Password = d.opt(l.Password)
		it.TOTP = d.opt(l.TOTP)
		for _, u := range l.URIs {
			uri := d.opt(u.URI)
			// A URI whose checksum does not match was swapped in by whoever
			// stores the data; the official clients drop it too.
			if u.URIChecksum != nil && *u.URIChecksum != "" {
				sum := sha256.Sum256([]byte(uri))
				if d.opt(u.URIChecksum) != base64.StdEncoding.EncodeToString(sum[:]) {
					continue
				}
			}
			it.URIs = append(it.URIs, URI{URI: uri, Match: u.Match})
		}
		it.fido2 = l.Fido2Credentials
		it.passwordRevised = l.PasswordRevisionDate
		it.autofill = l.AutofillOnPageLoad
	}
	if s := c.SSHKey; s != nil {
		it.SSH = &SSHKey{Private: d.opt(s.PrivateKey), Public: d.opt(s.PublicKey), Fingerprint: d.opt(s.KeyFingerprint)}
	}
	if c.Card != nil {
		it.Card = decryptNamed(d, cardFields(c.Card))
	}
	if c.Identity != nil {
		it.Identity = decryptNamed(d, identityFields(c.Identity))
	}
	for _, f := range c.Fields {
		it.Fields = append(it.Fields, Field{Name: d.opt(f.Name), Value: d.opt(f.Value), Kind: fieldKind(f.Type), LinkedID: f.LinkedID})
	}
	for _, h := range c.PasswordHistory {
		changed, _ := parseTime(h.LastUsedDate) // see Created above
		it.PasswordHistory = append(it.PasswordHistory, PasswordChange{Password: d.str(h.Password), Changed: changed})
	}
	for _, a := range c.Attachments {
		// The file name is encrypted with the item key; only the content has
		// its own key. Very old attachments carry no key of their own.
		att := Attachment{ID: a.ID, FileName: d.str(a.FileName), key: key}
		att.Size, _ = strconv.ParseInt(a.Size, 10, 64) // size is informational
		if a.Key != "" {
			ak, err := key.DecryptKey(a.Key)
			if err != nil && d.err == nil {
				d.err = fmt.Errorf("unwrap attachment key: %w", err)
			}
			att.key = ak
		}
		it.Attachments = append(it.Attachments, att)
	}
	if d.err != nil {
		return Item{}, d.err
	}
	return it, nil
}

func decryptNamed(d *decoder, fields []namedField) map[string]string {
	out := map[string]string{}
	for _, f := range fields {
		if v := d.opt(*f.ptr); v != "" {
			out[f.name] = v
		}
	}
	return out
}

// encoder encrypts the fields of one item, remembering the first failure.
type encoder struct {
	key keys.SymmetricKey
	err error
}

func (e *encoder) str(s string) string {
	if e.err != nil {
		return ""
	}
	out, err := e.key.EncryptString(s)
	if err != nil {
		e.err = err
	}
	return out
}

// opt encrypts a value, leaving an empty one null as the official clients do.
func (e *encoder) opt(s string) *string {
	if s == "" {
		return nil
	}
	v := e.str(s)
	return &v
}

// encryptItem produces the stored form of an item with its current key.
func encryptItem(it *Item) (bitwarden.Cipher, error) {
	code, ok := typeCodes[it.Type]
	if !ok {
		return bitwarden.Cipher{}, fmt.Errorf("%w %q", ErrUnknownType, it.Type)
	}
	e := &encoder{key: it.key}
	c := bitwarden.Cipher{
		Type:                  code,
		FolderID:              it.FolderID,
		Name:                  e.str(it.Name),
		Notes:                 e.opt(it.Notes),
		Key:                   it.wrappedKey,
		Favorite:              it.Favorite,
		Reprompt:              it.Reprompt,
		Fields:                []bitwarden.Field{},
		PasswordHistory:       []bitwarden.PasswordHistory{},
		LastKnownRevisionDate: it.revision,
	}
	if it.OrganizationID != "" {
		org := it.OrganizationID
		c.OrganizationID = &org
	}
	switch it.Type {
	case TypeLogin:
		login := &bitwarden.Login{
			Username:             e.opt(it.Username),
			Password:             e.opt(it.Password),
			TOTP:                 e.opt(it.TOTP),
			URIs:                 []bitwarden.URI{},
			Fido2Credentials:     it.fido2,
			PasswordRevisionDate: it.passwordRevised,
			AutofillOnPageLoad:   it.autofill,
		}
		for _, u := range it.URIs {
			sum := sha256.Sum256([]byte(u.URI))
			login.URIs = append(login.URIs, bitwarden.URI{
				URI:         e.opt(u.URI),
				URIChecksum: e.opt(base64.StdEncoding.EncodeToString(sum[:])),
				Match:       u.Match,
			})
		}
		c.Login = login
	case TypeNote:
		c.SecureNote = &bitwarden.SecureNote{Type: 0}
	case TypeSSHKey:
		ssh := it.SSH
		if ssh == nil {
			ssh = &SSHKey{}
		}
		c.SSHKey = &bitwarden.SSHKey{
			PrivateKey:     e.opt(ssh.Private),
			PublicKey:      e.opt(ssh.Public),
			KeyFingerprint: e.opt(ssh.Fingerprint),
		}
	case TypeCard:
		c.Card = &bitwarden.Card{}
		encryptNamed(e, cardFields(c.Card), it.Card)
	case TypeIdentity:
		c.Identity = &bitwarden.Identity{}
		encryptNamed(e, identityFields(c.Identity), it.Identity)
	}
	for _, f := range it.Fields {
		code, ok := fieldCodes[f.Kind]
		if !ok {
			code = bitwarden.FieldText
		}
		c.Fields = append(c.Fields, bitwarden.Field{Name: e.opt(f.Name), Value: e.opt(f.Value), Type: code, LinkedID: f.LinkedID})
	}
	for _, h := range it.PasswordHistory {
		c.PasswordHistory = append(c.PasswordHistory, bitwarden.PasswordHistory{
			Password:     e.str(h.Password),
			LastUsedDate: bitwarden.FormatTime(h.Changed),
		})
	}
	if e.err != nil {
		return bitwarden.Cipher{}, e.err
	}
	return c, nil
}

func encryptNamed(e *encoder, fields []namedField, values map[string]string) {
	for _, f := range fields {
		*f.ptr = e.opt(values[f.name])
	}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp: %w", err)
	}
	return t, nil
}
