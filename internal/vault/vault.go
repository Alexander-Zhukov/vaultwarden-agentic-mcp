// Package vault is the decrypted view of one Vaultwarden account: it logs in,
// keeps a synchronised snapshot, resolves items and collections by name, and
// performs every change with client-side encryption.
//
// Values are decrypted into memory only. Nothing in this package logs or
// returns a secret on its own initiative; the tool layer decides what a caller
// may see.
package vault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// Errors a caller must tell apart.
var (
	ErrNotFound  = errors.New("not found")
	ErrAmbiguous = errors.New("ambiguous reference")
	ErrInvalid   = errors.New("invalid request")
	ErrConflict  = errors.New("item changed since it was read")
	ErrReadOnly  = errors.New("read-only access")
)

// Config assembles a Vault.
type Config struct {
	// Server configures the API client; its Token field is supplied here.
	Server      bitwarden.Config
	Credentials Credentials
	// DeviceName is how this instance appears in the account's device list.
	DeviceName string
	// SyncTTL is how long a snapshot is served before a read syncs again.
	SyncTTL time.Duration
	// MaxAttachmentBytes bounds attachments read or written.
	MaxAttachmentBytes int64
	Clock              func() time.Time
	// OnLogin is told about every login attempt, for metrics.
	OnLogin func(err error)
	// TokenMargin, BackoffMin and BackoffMax tune the session; see
	// config.Tuning.
	TokenMargin time.Duration
	BackoffMin  time.Duration
	BackoffMax  time.Duration
}

// Organization is a membership of the account.
type Organization struct {
	ID   string
	Name string
	Role bitwarden.MemberType
	key  keys.SymmetricKey
}

// Collection is a collection the account can see.
type Collection struct {
	ID             string
	OrganizationID string
	Name           string
	ReadOnly       bool
	HidePasswords  bool
	Manage         bool
}

// BrokenItem is an item the account can see but not decrypt.
type BrokenItem struct {
	ID    string
	Error string
}

// Snapshot is one consistent, decrypted view of the account.
type Snapshot struct {
	At            time.Time
	Email         string
	UserID        string
	Organizations []Organization
	Collections   []Collection
	Items         []Item
	Broken        []BrokenItem
	Sends         []SendInfo
	userKey       keys.SymmetricKey
	private       keys.PrivateKey
}

// Vault is the decrypted view of one account. It is safe for concurrent use:
// reads share the current snapshot, writes are serialised so revision checks
// cannot race each other inside the process.
type Vault struct {
	client  *bitwarden.Client
	session *session
	ttl     time.Duration
	maxFile int64
	now     func() time.Time

	mu   sync.RWMutex
	snap *Snapshot

	syncMu  sync.Mutex
	writeMu sync.Mutex
}

// New validates the configuration. It does not contact the server; the first
// read or an explicit Refresh does.
func New(cfg Config) (*Vault, error) {
	switch {
	case cfg.Credentials.ClientID == "" || cfg.Credentials.ClientSecret.IsZero() || cfg.Credentials.Password.IsZero():
		return nil, errors.New("vault: client id, client secret and master password are required")
	case cfg.SyncTTL <= 0:
		return nil, errors.New("vault: SyncTTL must be positive")
	case cfg.MaxAttachmentBytes <= 0:
		return nil, errors.New("vault: MaxAttachmentBytes must be positive")
	case cfg.Clock == nil:
		return nil, errors.New("vault: Clock is required")
	case cfg.TokenMargin <= 0 || cfg.BackoffMin <= 0 || cfg.BackoffMax < cfg.BackoffMin:
		return nil, errors.New("vault: TokenMargin, BackoffMin and BackoffMax must be positive and ordered")
	}
	s := &session{
		creds:      cfg.Credentials,
		device:     deviceFor(cfg.Credentials.ClientID, cfg.DeviceName),
		now:        cfg.Clock,
		onLogin:    cfg.OnLogin,
		margin:     cfg.TokenMargin,
		backoffMin: cfg.BackoffMin,
		backoffMax: cfg.BackoffMax,
	}
	server := cfg.Server
	server.Token = s.Token
	client, err := bitwarden.New(server)
	if err != nil {
		return nil, err
	}
	s.client = client
	return &Vault{client: client, session: s, ttl: cfg.SyncTTL, maxFile: cfg.MaxAttachmentBytes, now: cfg.Clock}, nil
}

// retry runs an API call and, when the token was rejected, logs in again and
// retries once. A token can be revoked server-side long before it expires.
func (v *Vault) retry(fn func() error) error {
	sent := v.now()
	err := fn()
	if errors.Is(err, bitwarden.ErrUnauthorized) {
		v.session.Invalidate(sent)
		err = fn()
	}
	return err
}

// Snapshot returns a view no older than the sync TTL.
func (v *Vault) Snapshot(ctx context.Context) (*Snapshot, error) {
	v.mu.RLock()
	snap := v.snap
	v.mu.RUnlock()
	if snap != nil && v.now().Sub(snap.At) < v.ttl {
		return snap, nil
	}
	return v.Refresh(ctx)
}

// Current returns the last snapshot without contacting the server, or nil.
func (v *Vault) Current() *Snapshot {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.snap
}

// invalidate forgets the snapshot, so the next read syncs.
func (v *Vault) invalidate() {
	v.mu.Lock()
	v.snap = nil
	v.mu.Unlock()
}

// Refresh syncs now. Concurrent callers share one sync.
func (v *Vault) Refresh(ctx context.Context) (*Snapshot, error) {
	start := v.now()
	v.syncMu.Lock()
	defer v.syncMu.Unlock()
	// Another caller may have synced while this one waited. A snapshot counts
	// only if its request left after this call began, so a write that
	// finished before the call is always visible in what it returns.
	v.mu.RLock()
	if v.snap != nil && !v.snap.At.Before(start) {
		snap := v.snap
		v.mu.RUnlock()
		return snap, nil
	}
	v.mu.RUnlock()

	snap, err := v.sync(ctx)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.snap = snap
	return snap, nil
}

func (v *Vault) sync(ctx context.Context) (*Snapshot, error) {
	// Stamped before the request: the snapshot reflects the server no later
	// than this moment.
	at := v.now()
	var resp *bitwarden.SyncResponse
	err := v.retry(func() error {
		var err error
		resp, err = v.client.Sync(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sync: %w", err)
	}
	userKey, private, email, err := v.session.Keys(ctx)
	if err != nil {
		return nil, err
	}

	snap := &Snapshot{At: at, Email: email, UserID: resp.Profile.ID, userKey: userKey, private: private}
	orgKeys := map[string]keys.SymmetricKey{}
	for _, o := range resp.Profile.Organizations {
		// An invited but unconfirmed membership has no key yet.
		if o.Key == "" || o.Status != bitwarden.MemberConfirmed {
			continue
		}
		k, err := private.DecryptKey(o.Key)
		if err != nil {
			// That organization's items come out as undecryptable; the rest
			// of the account stays readable.
			continue
		}
		orgKeys[o.ID] = k
		snap.Organizations = append(snap.Organizations, Organization{ID: o.ID, Name: o.Name, Role: o.Type, key: k})
	}
	for _, c := range resp.Collections {
		k, ok := orgKeys[c.OrganizationID]
		if !ok {
			continue
		}
		name, err := k.DecryptString(c.Name)
		if err != nil {
			name = "[undecryptable " + c.ID + "]"
		}
		snap.Collections = append(snap.Collections, Collection{
			ID: c.ID, OrganizationID: c.OrganizationID, Name: name,
			ReadOnly: c.ReadOnly, HidePasswords: c.HidePasswords, Manage: c.Manage,
		})
	}
	sort.Slice(snap.Collections, func(i, j int) bool { return snap.Collections[i].Name < snap.Collections[j].Name })

	for _, c := range resp.Ciphers {
		owner := userKey
		if c.OrganizationID != nil {
			k, ok := orgKeys[*c.OrganizationID]
			if !ok {
				snap.Broken = append(snap.Broken, BrokenItem{ID: c.ID, Error: "organization key unavailable"})
				continue
			}
			owner = k
		}
		it, err := decryptCipher(c, owner)
		if err != nil {
			snap.Broken = append(snap.Broken, BrokenItem{ID: c.ID, Error: err.Error()})
			continue
		}
		snap.Items = append(snap.Items, it)
	}
	sort.Slice(snap.Items, func(i, j int) bool { return snap.Items[i].Name < snap.Items[j].Name })

	for _, s := range resp.Sends {
		snap.Sends = append(snap.Sends, decryptSendInfo(s, userKey))
	}
	return snap, nil
}

// Collection resolves a collection by id or name. Names match exactly first,
// then case-insensitively; a name shared by two collections is an error that
// lists both, never a guess.
func (s *Snapshot) Collection(ref string) (Collection, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Collection{}, fmt.Errorf("%w: collection is required", ErrInvalid)
	}
	var exact, folded []Collection
	for _, c := range s.Collections {
		switch {
		case c.ID == ref:
			return c, nil
		case c.Name == ref:
			exact = append(exact, c)
		case strings.EqualFold(c.Name, ref):
			folded = append(folded, c)
		}
	}
	for _, set := range [][]Collection{exact, folded} {
		switch len(set) {
		case 0:
			continue
		case 1:
			return set[0], nil
		default:
			ids := make([]string, len(set))
			for i, c := range set {
				ids[i] = c.ID
			}
			return Collection{}, fmt.Errorf("%w: collection %q matches %s; pass the id", ErrAmbiguous, ref, strings.Join(ids, ", "))
		}
	}
	return Collection{}, fmt.Errorf("%w: collection %q", ErrNotFound, ref)
}

// CollectionName returns the name of a collection id, or the id itself.
func (s *Snapshot) CollectionName(id string) string {
	for _, c := range s.Collections {
		if c.ID == id {
			return c.Name
		}
	}
	return id
}

// Organization returns a membership by id.
func (s *Snapshot) Organization(id string) (Organization, bool) {
	for _, o := range s.Organizations {
		if o.ID == id {
			return o, true
		}
	}
	return Organization{}, false
}

// ItemRef names an item: by id, or by name within an optional collection.
type ItemRef struct {
	Ref        string
	Collection string
	// Trash looks in the trash instead of the live items. An id resolves
	// either way.
	Trash bool
}

// Item resolves a reference the same way collections are resolved. An
// ambiguous name lists every candidate with its collection, so the caller can
// retry with an id instead of acting on the wrong secret.
func (s *Snapshot) Item(ref ItemRef) (*Item, error) {
	name := strings.TrimSpace(ref.Ref)
	if name == "" {
		return nil, fmt.Errorf("%w: item is required", ErrInvalid)
	}
	var within string
	if ref.Collection != "" {
		c, err := s.Collection(ref.Collection)
		if err != nil {
			return nil, err
		}
		within = c.ID
	}
	var exact, folded []*Item
	for i := range s.Items {
		it := &s.Items[i]
		if (it.Deleted != nil) != ref.Trash && it.ID != name {
			continue
		}
		if within != "" && !slices.Contains(it.CollectionIDs, within) {
			continue
		}
		switch {
		case it.ID == name:
			return it, nil
		case it.Name == name:
			exact = append(exact, it)
		case strings.EqualFold(it.Name, name):
			folded = append(folded, it)
		}
	}
	for _, set := range [][]*Item{exact, folded} {
		switch len(set) {
		case 0:
			continue
		case 1:
			return set[0], nil
		default:
			parts := make([]string, len(set))
			for i, it := range set {
				parts[i] = fmt.Sprintf("%s (in %s)", it.ID, s.collectionList(it.CollectionIDs))
			}
			return nil, fmt.Errorf("%w: item %q matches %s; pass the id or a collection", ErrAmbiguous, name, strings.Join(parts, ", "))
		}
	}
	return nil, fmt.Errorf("%w: item %q", ErrNotFound, name)
}

func (s *Snapshot) collectionList(ids []string) string {
	if len(ids) == 0 {
		return "no collection"
	}
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = s.CollectionName(id)
	}
	return strings.Join(names, ", ")
}

// CollectionNames maps collection ids to names.
func (s *Snapshot) CollectionNames(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = s.CollectionName(id)
	}
	return out
}

// ownerKey returns the key an item of the given organization is encrypted
// with at the top level.
func (s *Snapshot) ownerKey(orgID string) (keys.SymmetricKey, error) {
	if orgID == "" {
		return s.userKey, nil
	}
	o, ok := s.Organization(orgID)
	if !ok {
		return keys.SymmetricKey{}, fmt.Errorf("%w: organization %s", ErrNotFound, orgID)
	}
	return o.key, nil
}
