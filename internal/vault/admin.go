package vault

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// Role is a member role as tools spell it.
type Role string

// Member roles. Custom roles exist in the protocol but not in Vaultwarden.
const (
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleUser    Role = "user"
)

var roleCodes = map[Role]bitwarden.MemberType{
	RoleOwner: bitwarden.MemberOwner, RoleAdmin: bitwarden.MemberAdmin,
	RoleManager: bitwarden.MemberManager, RoleUser: bitwarden.MemberUser,
}

// ParseRole validates a tool-supplied role.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if _, ok := roleCodes[r]; !ok {
		return "", fmt.Errorf("%w: role %q: want owner, admin, manager or user", ErrInvalid, s)
	}
	return r, nil
}

// RoleOf names a member type as tools spell it.
func RoleOf(t bitwarden.MemberType) Role { return roleName(t) }

// StatusOf names a membership status as tools spell it.
func StatusOf(s bitwarden.MemberStatus) string { return statusName(s) }

func roleName(t bitwarden.MemberType) Role {
	// Vaultwarden reports managers as the custom type.
	if t == bitwarden.MemberCustom {
		return RoleManager
	}
	for name, code := range roleCodes {
		if code == t {
			return name
		}
	}
	return Role(fmt.Sprintf("type_%d", t))
}

func statusName(s bitwarden.MemberStatus) string {
	switch s {
	case bitwarden.MemberRevoked:
		return "revoked"
	case bitwarden.MemberInvited:
		return "invited"
	case bitwarden.MemberAccepted:
		return "accepted"
	case bitwarden.MemberConfirmed:
		return "confirmed"
	default:
		return fmt.Sprintf("status_%d", s)
	}
}

// Access is one grant of a collection.
type Access struct {
	CollectionID  string
	Collection    string
	ReadOnly      bool
	HidePasswords bool
	Manage        bool
}

// Member is an organization membership.
type Member struct {
	ID          string
	UserID      string
	Email       string
	Name        string
	Status      string
	Role        Role
	AccessAll   bool
	Collections []Access
}

// AdminCollection is a collection with every member granted access to it.
type AdminCollection struct {
	ID      string
	Name    string
	Members []MemberAccess
	Items   int
	// groups are carried back on update, which replaces them wholesale.
	groups []bitwarden.CollectionAccess
}

// MemberAccess is a member's grant on one collection. Member is an email or a
// membership id on input, the email on output.
type MemberAccess struct {
	Member        string
	ReadOnly      bool
	HidePasswords bool
	Manage        bool
}

// Grant is a collection grant on input: the collection by name or id.
type Grant struct {
	Collection    string
	ReadOnly      bool
	HidePasswords bool
	Manage        bool
}

// Admin performs organization management for one organization.
type Admin struct {
	v       *Vault
	orgID   string
	orgName string
}

// ManagedOrganization is a membership of the account and whether this
// instance manages it.
type ManagedOrganization struct {
	ID      string
	Name    string
	Role    Role
	Managed bool
}

// Organizations lists the account's memberships. An organization is managed
// when the account owns or administers it and it is within allowed (see
// withinAllowed; empty allows every one).
func (v *Vault) Organizations(ctx context.Context, allowed []string) ([]ManagedOrganization, error) {
	snap, err := v.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ManagedOrganization, 0, len(snap.Organizations))
	for _, o := range snap.Organizations {
		out = append(out, ManagedOrganization{
			ID: o.ID, Name: o.Name, Role: roleName(o.Role),
			Managed: administers(o) && withinAllowed(o, allowed, snap.Organizations),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func administers(o Organization) bool {
	return o.Role == bitwarden.MemberOwner || o.Role == bitwarden.MemberAdmin
}

var idShape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// withinAllowed matches the allow-list exactly: an entry is an organization id,
// or the exact name of one organization. Anyone on the server can create an
// organization and invite this account, so a looser match — ignoring case, or
// a name shared by two organizations — would let a newcomer into the list.
func withinAllowed(o Organization, allowed []string, all []Organization) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, ref := range allowed {
		if o.ID == ref {
			return true
		}
		// An id-shaped entry names an id, never a name that copies one.
		if o.Name == ref && !idShape.MatchString(ref) {
			named := 0
			for _, other := range all {
				if other.Name == ref {
					named++
				}
			}
			if named == 1 {
				return true
			}
		}
	}
	return false
}

// Admin returns the management view of one organization. orgRef names it by
// name or id; empty picks the only managed organization. allowed bounds which
// organizations may be managed at all (empty allows every one the account
// owns or administers).
func (v *Vault) Admin(ctx context.Context, orgRef string, allowed []string) (*Admin, error) {
	snap, err := v.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if orgRef != "" {
		// An id wins over names: a name can be chosen by anyone who creates an
		// organization, an id cannot.
		var matches []Organization
		for _, o := range snap.Organizations {
			if o.ID == orgRef {
				matches = []Organization{o}
				break
			}
			if strings.EqualFold(o.Name, orgRef) {
				matches = append(matches, o)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("%w: organization %q", ErrNotFound, orgRef)
		case 1:
		default:
			return nil, fmt.Errorf("%w: organization %q matches %d organizations; pass the id", ErrAmbiguous, orgRef, len(matches))
		}
		o := matches[0]
		if !withinAllowed(o, allowed, snap.Organizations) {
			return nil, fmt.Errorf("%w: organization %q is not managed by this instance", ErrReadOnly, o.Name)
		}
		if !administers(o) {
			return nil, fmt.Errorf("%w: the account is %s of %q, not owner or admin", ErrReadOnly, roleName(o.Role), o.Name)
		}
		return &Admin{v: v, orgID: o.ID, orgName: o.Name}, nil
	}
	var managed []Organization
	for _, o := range snap.Organizations {
		if administers(o) && withinAllowed(o, allowed, snap.Organizations) {
			managed = append(managed, o)
		}
	}
	switch len(managed) {
	case 0:
		return nil, fmt.Errorf("%w: this instance manages no organization: the account owns or administers none of those it may manage", ErrNotFound)
	case 1:
		return &Admin{v: v, orgID: managed[0].ID, orgName: managed[0].Name}, nil
	default:
		names := make([]string, len(managed))
		for i, o := range managed {
			names[i] = o.Name
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w: this instance manages several organizations (%s); pass organization", ErrAmbiguous, strings.Join(names, ", "))
	}
}

// OrganizationID returns the managed organization.
func (a *Admin) OrganizationID() string { return a.orgID }

// OrganizationName returns the managed organization's name.
func (a *Admin) OrganizationName() string { return a.orgName }

func (a *Admin) orgKey(ctx context.Context) (*Snapshot, keys.SymmetricKey, error) {
	snap, err := a.v.Snapshot(ctx)
	if err != nil {
		return nil, keys.SymmetricKey{}, err
	}
	o, ok := snap.Organization(a.orgID)
	if !ok {
		return nil, keys.SymmetricKey{}, fmt.Errorf("%w: organization %s", ErrNotFound, a.orgID)
	}
	return snap, o.key, nil
}

func (a *Admin) rawMembers(ctx context.Context) ([]bitwarden.Member, error) {
	var out []bitwarden.Member
	err := a.v.retry(func() error {
		var err error
		out, err = a.v.client.Members(ctx, a.orgID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return out, nil
}

// Members lists memberships with their collection grants.
func (a *Admin) Members(ctx context.Context) ([]Member, error) {
	snap, _, err := a.orgKey(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(raw))
	for _, m := range raw {
		mem := Member{
			ID: m.ID, UserID: m.UserID, Email: m.Email, Name: m.Name,
			Status: statusName(m.Status), Role: roleName(m.Type), AccessAll: m.AccessAll,
		}
		for _, c := range m.Collections {
			mem.Collections = append(mem.Collections, Access{
				CollectionID: c.ID, Collection: snap.CollectionName(c.ID),
				ReadOnly: c.ReadOnly, HidePasswords: c.HidePasswords, Manage: c.Manage,
			})
		}
		out = append(out, mem)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func findMember(members []bitwarden.Member, ref string) (bitwarden.Member, error) {
	for _, m := range members {
		if m.ID == ref || m.UserID == ref || strings.EqualFold(m.Email, ref) {
			return m, nil
		}
	}
	return bitwarden.Member{}, fmt.Errorf("%w: member %q", ErrNotFound, ref)
}

func (a *Admin) grants(snap *Snapshot, in []Grant) ([]bitwarden.CollectionAccess, error) {
	out := make([]bitwarden.CollectionAccess, 0, len(in))
	for _, g := range in {
		c, err := snap.CollectionIn(a.orgID, g.Collection)
		if err != nil {
			return nil, err
		}
		out = append(out, bitwarden.CollectionAccess{ID: c.ID, ReadOnly: g.ReadOnly, HidePasswords: g.HidePasswords, Manage: g.Manage})
	}
	return out, nil
}

// memberRequest takes the server's own role code, never a name looked up in a
// table: a code missing from the table would read as zero, which is owner.
func memberRequest(typ bitwarden.MemberType, access []bitwarden.CollectionAccess, groups []string) bitwarden.MemberRequest {
	if access == nil {
		access = []bitwarden.CollectionAccess{}
	}
	if groups == nil {
		groups = []string{}
	}
	return bitwarden.MemberRequest{
		Type:        typ,
		Collections: access,
		Groups:      groups,
		Permissions: map[string]bool{},
	}
}

// Invite sends an invitation with a role and collection grants.
func (a *Admin) Invite(ctx context.Context, email string, role Role, grants []Grant) error {
	if !strings.Contains(email, "@") {
		return fmt.Errorf("%w: %q is not an email address", ErrInvalid, email)
	}
	snap, _, err := a.orgKey(ctx)
	if err != nil {
		return err
	}
	access, err := a.grants(snap, grants)
	if err != nil {
		return err
	}
	code, ok := roleCodes[role]
	if !ok {
		return fmt.Errorf("%w: role %q", ErrInvalid, role)
	}
	req := memberRequest(code, access, nil)
	req.Emails = []string{email}
	return a.v.retry(func() error { return a.v.client.InviteMembers(ctx, a.orgID, req) })
}

// ErrFingerprintMismatch means the member's key is not the one the operator
// verified: the server may be handing out a key that is not the member's.
var ErrFingerprintMismatch = errors.New("fingerprint phrase does not match the member's key")

// Confirm completes an accepted membership by wrapping the organization key for
// the member's public key. It always returns the key's fingerprint phrase — the
// one the member's own client shows. With an empty expected phrase nothing is
// confirmed: the phrase comes back for the operator to compare. With a phrase,
// the key is trusted only if it matches.
func (a *Admin) Confirm(ctx context.Context, memberRef, expected string) (Member, string, error) {
	_, orgKey, err := a.orgKey(ctx)
	if err != nil {
		return Member{}, "", err
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return Member{}, "", err
	}
	m, err := findMember(raw, memberRef)
	if err != nil {
		return Member{}, "", err
	}
	if m.Status != bitwarden.MemberAccepted {
		return Member{}, "", fmt.Errorf("%w: member %s is %s; only an accepted invitation can be confirmed", ErrInvalid, m.Email, statusName(m.Status))
	}
	var spki string
	err = a.v.retry(func() error {
		var err error
		spki, err = a.v.client.UserPublicKey(ctx, m.UserID)
		return err
	})
	if err != nil {
		return Member{}, "", fmt.Errorf("fetch public key: %w", err)
	}
	pub, err := keys.ParsePublicKey(spki)
	if err != nil {
		return Member{}, "", err
	}
	phrase, err := pub.FingerprintPhrase(m.UserID)
	if err != nil {
		return Member{}, "", err
	}
	pending := Member{ID: m.ID, UserID: m.UserID, Email: m.Email, Status: "accepted", Role: roleName(m.Type)}
	if strings.TrimSpace(expected) == "" {
		return pending, phrase, nil
	}
	if !strings.EqualFold(strings.TrimSpace(expected), phrase) {
		return pending, phrase, ErrFingerprintMismatch
	}
	wrapped, err := pub.EncryptKey(orgKey)
	if err != nil {
		return Member{}, "", err
	}
	if err := a.v.retry(func() error { return a.v.client.ConfirmMember(ctx, a.orgID, m.ID, wrapped) }); err != nil {
		return Member{}, "", fmt.Errorf("confirm member: %w", err)
	}
	return Member{ID: m.ID, UserID: m.UserID, Email: m.Email, Status: "confirmed", Role: roleName(m.Type)}, phrase, nil
}

// UpdateMember changes a member's role, collection grants, or both. A nil
// role or nil grants keeps the current value.
func (a *Admin) UpdateMember(ctx context.Context, memberRef string, role *Role, grants []Grant) error {
	snap, _, err := a.orgKey(ctx)
	if err != nil {
		return err
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return err
	}
	m, err := findMember(raw, memberRef)
	if err != nil {
		return err
	}
	typ := m.Type
	if role != nil {
		code, ok := roleCodes[*role]
		if !ok {
			return fmt.Errorf("%w: role %q", ErrInvalid, *role)
		}
		typ = code
	}
	access := m.Collections
	if grants != nil {
		access, err = a.grants(snap, grants)
		if err != nil {
			return err
		}
	}
	req := memberRequest(typ, access, m.Groups)
	req.AccessAll = m.AccessAll
	// A manager of every collection is the custom type with three
	// permissions; Vaultwarden derives the access from them and ignores
	// accessAll. Sent back as a plain manager, the member would silently lose
	// every collection.
	if m.Type == bitwarden.MemberCustom && m.AccessAll && (role == nil || *role == RoleManager) {
		req.Type = bitwarden.MemberCustom
		req.Permissions = map[string]bool{"editAnyCollection": true, "deleteAnyCollection": true, "createNewCollections": true}
	}
	if err := a.v.retry(func() error { return a.v.client.UpdateMember(ctx, a.orgID, m.ID, req) }); err != nil {
		return fmt.Errorf("update member: %w", err)
	}
	_, err = a.v.Refresh(ctx)
	return err
}

// MemberRole returns a member's current role, so a caller can refuse to act
// on an owner or admin.
func (a *Admin) MemberRole(ctx context.Context, memberRef string) (Role, error) {
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return "", err
	}
	m, err := findMember(raw, memberRef)
	if err != nil {
		return "", err
	}
	return roleName(m.Type), nil
}

// MemberAction is a lifecycle change of a membership.
type MemberAction string

// Lifecycle changes.
const (
	ActionRevoke  MemberAction = "revoke"
	ActionRestore MemberAction = "restore"
	ActionRemove  MemberAction = "remove"
)

// ChangeMember revokes, restores or removes a membership. The account cannot
// act on its own membership: locking the only admin out is not recoverable
// from here.
func (a *Admin) ChangeMember(ctx context.Context, memberRef string, action MemberAction) (Member, error) {
	snap, err := a.v.Snapshot(ctx)
	if err != nil {
		return Member{}, err
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return Member{}, err
	}
	m, err := findMember(raw, memberRef)
	if err != nil {
		return Member{}, err
	}
	if m.UserID == snap.UserID {
		return Member{}, fmt.Errorf("%w: refusing to %s this service's own membership", ErrInvalid, action)
	}
	var call func() error
	switch action {
	case ActionRevoke:
		call = func() error { return a.v.client.RevokeMember(ctx, a.orgID, m.ID) }
	case ActionRestore:
		call = func() error { return a.v.client.RestoreMember(ctx, a.orgID, m.ID) }
	case ActionRemove:
		call = func() error { return a.v.client.RemoveMember(ctx, a.orgID, m.ID) }
	default:
		return Member{}, fmt.Errorf("%w: action %q", ErrInvalid, action)
	}
	if err := a.v.retry(call); err != nil {
		return Member{}, fmt.Errorf("%s member: %w", action, err)
	}
	return Member{ID: m.ID, UserID: m.UserID, Email: m.Email, Role: roleName(m.Type)}, nil
}

// Collections lists every collection of the organization with its members,
// including collections the account itself is not assigned to.
func (a *Admin) Collections(ctx context.Context) ([]AdminCollection, error) {
	snap, orgKey, err := a.orgKey(ctx)
	if err != nil {
		return nil, err
	}
	var details []bitwarden.CollectionDetails
	err = a.v.retry(func() error {
		var err error
		details, err = a.v.client.OrgCollections(ctx, a.orgID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list collections: %w", err)
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return nil, err
	}
	email := func(memberID string) string {
		for _, m := range raw {
			if m.ID == memberID {
				return m.Email
			}
		}
		return memberID
	}
	out := make([]AdminCollection, 0, len(details))
	for _, d := range details {
		name, err := orgKey.DecryptString(d.Name)
		if err != nil {
			name = "[undecryptable]"
		}
		c := AdminCollection{ID: d.ID, Name: name, groups: d.Groups}
		for _, u := range d.Users {
			c.Members = append(c.Members, MemberAccess{Member: email(u.ID), ReadOnly: u.ReadOnly, HidePasswords: u.HidePasswords, Manage: u.Manage})
		}
		for i := range snap.Items {
			if snap.Items[i].Deleted == nil && slices.Contains(snap.Items[i].CollectionIDs, d.ID) {
				c.Items++
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (a *Admin) memberAccess(raw []bitwarden.Member, in []MemberAccess) ([]bitwarden.CollectionAccess, error) {
	out := make([]bitwarden.CollectionAccess, 0, len(in))
	for _, g := range in {
		m, err := findMember(raw, g.Member)
		if err != nil {
			return nil, err
		}
		out = append(out, bitwarden.CollectionAccess{ID: m.ID, ReadOnly: g.ReadOnly, HidePasswords: g.HidePasswords, Manage: g.Manage})
	}
	return out, nil
}

// CreateCollection adds a collection with the given member grants.
func (a *Admin) CreateCollection(ctx context.Context, name string, members []MemberAccess) (Collection, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Collection{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	snap, orgKey, err := a.orgKey(ctx)
	if err != nil {
		return Collection{}, err
	}
	for _, c := range snap.Collections {
		if c.OrganizationID == a.orgID && strings.EqualFold(c.Name, name) {
			return Collection{}, fmt.Errorf("%w: collection %q already exists", ErrInvalid, c.Name)
		}
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return Collection{}, err
	}
	users, err := a.memberAccess(raw, members)
	if err != nil {
		return Collection{}, err
	}
	encName, err := orgKey.EncryptString(name)
	if err != nil {
		return Collection{}, err
	}
	var created *bitwarden.Collection
	err = a.v.retry(func() error {
		var err error
		created, err = a.v.client.CreateCollection(ctx, a.orgID, bitwarden.CollectionRequest{
			Name: encName, Groups: []bitwarden.CollectionAccess{}, Users: users,
		})
		return err
	})
	if err != nil {
		return Collection{}, fmt.Errorf("create collection: %w", err)
	}
	if _, err := a.v.Refresh(ctx); err != nil {
		return Collection{}, err
	}
	return Collection{ID: created.ID, OrganizationID: a.orgID, Name: name}, nil
}

// UpdateCollection renames a collection, replaces its member grants, or both.
// A nil members list keeps the current grants.
func (a *Admin) UpdateCollection(ctx context.Context, ref, newName string, members []MemberAccess) (AdminCollection, error) {
	cols, err := a.Collections(ctx)
	if err != nil {
		return AdminCollection{}, err
	}
	target, err := pickCollection(cols, ref)
	if err != nil {
		return AdminCollection{}, err
	}
	_, orgKey, err := a.orgKey(ctx)
	if err != nil {
		return AdminCollection{}, err
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return AdminCollection{}, err
	}
	if members == nil {
		members = target.Members
	}
	users, err := a.memberAccess(raw, members)
	if err != nil {
		return AdminCollection{}, err
	}
	name := target.Name
	if strings.TrimSpace(newName) != "" {
		name = strings.TrimSpace(newName)
	}
	encName, err := orgKey.EncryptString(name)
	if err != nil {
		return AdminCollection{}, err
	}
	err = a.v.retry(func() error {
		_, err := a.v.client.UpdateCollection(ctx, a.orgID, target.ID, bitwarden.CollectionRequest{
			Name: encName, Groups: groupsOrEmpty(target.groups), Users: users,
		})
		return err
	})
	if err != nil {
		return AdminCollection{}, fmt.Errorf("update collection: %w", err)
	}
	if _, err := a.v.Refresh(ctx); err != nil {
		return AdminCollection{}, err
	}
	target.Name, target.Members = name, members
	return target, nil
}

// DeleteCollection removes an empty collection. A collection with items is
// refused: deleting it would leave its items in no collection, visible only to
// owners and admins.
func (a *Admin) DeleteCollection(ctx context.Context, ref string) (AdminCollection, error) {
	cols, err := a.Collections(ctx)
	if err != nil {
		return AdminCollection{}, err
	}
	target, err := pickCollection(cols, ref)
	if err != nil {
		return AdminCollection{}, err
	}
	if target.Items > 0 {
		return AdminCollection{}, fmt.Errorf("%w: collection %q still holds %d items; move them first", ErrInvalid, target.Name, target.Items)
	}
	if err := a.v.retry(func() error { return a.v.client.DeleteCollection(ctx, a.orgID, target.ID) }); err != nil {
		return AdminCollection{}, fmt.Errorf("delete collection: %w", err)
	}
	_, err = a.v.Refresh(ctx)
	return target, err
}

func pickCollection(cols []AdminCollection, ref string) (AdminCollection, error) {
	var byName []AdminCollection
	for _, c := range cols {
		if c.ID == ref {
			return c, nil
		}
		if strings.EqualFold(c.Name, ref) {
			byName = append(byName, c)
		}
	}
	switch len(byName) {
	case 0:
		return AdminCollection{}, fmt.Errorf("%w: collection %q", ErrNotFound, ref)
	case 1:
		return byName[0], nil
	default:
		return AdminCollection{}, fmt.Errorf("%w: collection %q matches %d collections; pass the id", ErrAmbiguous, ref, len(byName))
	}
}

// Event is a decoded entry of the organization event log.
type Event struct {
	Time       time.Time
	Type       string
	Actor      string
	Member     string
	ItemID     string
	Item       string
	Collection string
	IP         string
}

// eventNames covers the events an operator of a machine vault looks for.
var eventNames = map[int]string{
	1000: "user_logged_in", 1001: "user_changed_password", 1005: "user_failed_login",
	1007: "user_exported_vault",
	1100: "item_created", 1101: "item_updated", 1102: "item_deleted",
	1103: "attachment_created", 1104: "attachment_deleted", 1105: "item_shared",
	1106: "item_collections_updated", 1107: "item_viewed", 1108: "password_revealed",
	1109: "hidden_field_revealed", 1111: "password_copied", 1112: "hidden_field_copied",
	1115: "item_trashed", 1116: "item_restored",
	1300: "collection_created", 1301: "collection_updated", 1302: "collection_deleted",
	1500: "member_invited", 1501: "member_confirmed", 1502: "member_updated",
	1503: "member_removed", 1511: "member_revoked", 1512: "member_restored",
	1600: "organization_updated",
}

// Events reads the event log between two moments, newest first, up to limit
// entries. Vaultwarden records events only when organization events are
// enabled on the server.
func (a *Admin) Events(ctx context.Context, from, to time.Time, limit int) ([]Event, error) {
	snap, err := a.v.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := a.rawMembers(ctx)
	if err != nil {
		return nil, err
	}
	byUser := map[string]string{}
	byMember := map[string]string{}
	for _, m := range raw {
		byUser[m.UserID] = m.Email
		byMember[m.ID] = m.Email
	}
	itemName := func(id string) string {
		for i := range snap.Items {
			if snap.Items[i].ID == id {
				return snap.Items[i].Name
			}
		}
		return ""
	}
	var out []Event
	token := ""
	for len(out) < limit {
		var page []bitwarden.Event
		err := a.v.retry(func() error {
			var err error
			page, token, err = a.v.client.Events(ctx, a.orgID, from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339), token)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("read events: %w", err)
		}
		for _, e := range page {
			ev := Event{Type: eventNames[e.Type]}
			if ev.Type == "" {
				ev.Type = fmt.Sprintf("event_%d", e.Type)
			}
			ev.Time, _ = parseTime(e.Date) // informational
			if e.ActingUserID != nil {
				ev.Actor = byUser[*e.ActingUserID]
			}
			if e.MemberID != nil {
				ev.Member = byMember[*e.MemberID]
			}
			if e.CipherID != nil {
				ev.ItemID = *e.CipherID
				ev.Item = itemName(*e.CipherID)
			}
			if e.CollectionID != nil {
				ev.Collection = snap.CollectionName(*e.CollectionID)
			}
			if e.IPAddress != nil {
				ev.IP = *e.IPAddress
			}
			out = append(out, ev)
			if len(out) == limit {
				break
			}
		}
		if token == "" || len(page) == 0 {
			break
		}
	}
	return out, nil
}

func groupsOrEmpty(g []bitwarden.CollectionAccess) []bitwarden.CollectionAccess {
	if g == nil {
		return []bitwarden.CollectionAccess{}
	}
	return g
}
