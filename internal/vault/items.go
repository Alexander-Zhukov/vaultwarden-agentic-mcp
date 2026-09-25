package vault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
)

// passwordHistoryLimit matches the official clients: the five most recent
// passwords are kept.
const passwordHistoryLimit = 5

// NewItem is what a caller supplies to create an item. Every item is created
// directly in its collections; an organization item never passes through the
// account's personal vault.
type NewItem struct {
	Collections []string
	Type        ItemType
	Name        string
	Notes       string
	Username    string
	Password    string
	TOTP        string
	URIs        []URI
	Fields      []Field
	SSH         *SSHKey
	Card        map[string]string
	Identity    map[string]string
}

func (v *Vault) mutate(ctx context.Context, fn func(snap *Snapshot) error) error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	// Writes always start from a fresh view: acting on a stale snapshot is how
	// an update overwrites a change it never saw.
	snap, err := v.Refresh(ctx)
	if err != nil {
		return err
	}
	if err := fn(snap); err != nil {
		return err
	}
	// The write succeeded; a failed sync after it must not be reported as a
	// failed write, or the caller retries and creates a duplicate. The stale
	// snapshot is dropped instead, so the next read syncs.
	if _, err := v.Refresh(ctx); err != nil {
		v.invalidate()
	}
	return nil
}

// resolveWritable resolves collection references and checks that the account
// may write to every one of them and that they share one organization.
func resolveWritable(snap *Snapshot, refs []string) ([]Collection, error) {
	return resolveWritableIn(snap, "", refs)
}

// resolveWritableIn resolves writable collections within one organization; an
// empty orgID accepts any, as long as all of them share one.
func resolveWritableIn(snap *Snapshot, orgID string, refs []string) ([]Collection, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("%w: at least one collection is required", ErrInvalid)
	}
	var out []Collection
	for _, ref := range refs {
		c, err := snap.CollectionIn(orgID, ref)
		if errors.Is(err, ErrNotFound) && orgID != "" {
			if _, elsewhere := snap.Collection(ref); elsewhere == nil {
				return nil, fmt.Errorf("%w: collection %q is in another organization; an item cannot change organization", ErrInvalid, ref)
			}
		}
		if err != nil {
			return nil, err
		}
		if c.ReadOnly {
			return nil, fmt.Errorf("%w: collection %q", ErrReadOnly, c.Name)
		}
		if len(out) > 0 && out[0].OrganizationID != c.OrganizationID {
			return nil, fmt.Errorf("%w: collections belong to different organizations", ErrInvalid)
		}
		if !slices.ContainsFunc(out, func(x Collection) bool { return x.ID == c.ID }) {
			out = append(out, c)
		}
	}
	return out, nil
}

func ids(cs []Collection) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

// Create stores a new item and returns it as the server saw it.
func (v *Vault) Create(ctx context.Context, n NewItem) (Item, error) {
	if strings.TrimSpace(n.Name) == "" {
		return Item{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if _, ok := typeCodes[n.Type]; !ok {
		return Item{}, fmt.Errorf("%w %q", ErrUnknownType, n.Type)
	}
	var created Item
	err := v.mutate(ctx, func(snap *Snapshot) error {
		cols, err := resolveWritable(snap, n.Collections)
		if err != nil {
			return err
		}
		key, err := snap.ownerKey(cols[0].OrganizationID)
		if err != nil {
			return err
		}
		it := Item{
			OrganizationID: cols[0].OrganizationID,
			Type:           n.Type, Name: n.Name, Notes: n.Notes,
			Username: n.Username, Password: n.Password, TOTP: n.TOTP, URIs: n.URIs,
			Fields: n.Fields, SSH: n.SSH, Card: n.Card, Identity: n.Identity,
			key: key,
		}
		c, err := encryptItem(&it)
		if err != nil {
			return err
		}
		var resp *bitwarden.Cipher
		err = v.retry(func() error {
			var err error
			resp, err = v.client.CreateCipher(ctx, c, ids(cols))
			return err
		})
		if err != nil {
			return fmt.Errorf("create item: %w", err)
		}
		created, err = decryptCipher(*resp, key)
		if err != nil {
			return err
		}
		if len(created.CollectionIDs) == 0 {
			created.CollectionIDs = ids(cols)
		}
		return nil
	})
	return created, err
}

// Update applies change to a copy of the item and stores it. A changed password
// pushes the previous one into the history, as every Bitwarden client does, so
// a rotation can always be rolled back by hand.
func (v *Vault) Update(ctx context.Context, ref ItemRef, change func(*Item) error) (Item, error) {
	var updated Item
	err := v.mutate(ctx, func(snap *Snapshot) error {
		current, err := snap.Item(ref)
		if err != nil {
			return err
		}
		if err := checkEditable(snap, current); err != nil {
			return err
		}
		next := cloneItem(current)
		if err := change(&next); err != nil {
			return err
		}
		recordHistory(current, &next, v.now())
		c, err := encryptItem(&next)
		if err != nil {
			return err
		}
		var resp *bitwarden.Cipher
		err = v.retry(func() error {
			var err error
			resp, err = v.client.UpdateCipher(ctx, current.ID, c)
			return err
		})
		if err != nil {
			return conflictOr(fmt.Errorf("update item: %w", err))
		}
		key, err := snap.ownerKey(current.OrganizationID)
		if err != nil {
			return err
		}
		updated, err = decryptCipher(*resp, key)
		if err != nil {
			return err
		}
		if len(updated.CollectionIDs) == 0 {
			updated.CollectionIDs = current.CollectionIDs
		}
		return nil
	})
	return updated, err
}

// conflictOr recognises the server's refusal of a stale revision.
func conflictOr(err error) error {
	var apiErr *bitwarden.APIError
	if errors.As(err, &apiErr) && strings.Contains(strings.ToLower(apiErr.Message), "out of date") {
		return errors.Join(ErrConflict, err)
	}
	return err
}

func checkEditable(snap *Snapshot, it *Item) error {
	if it.OrganizationID == "" {
		return nil
	}
	for _, id := range it.CollectionIDs {
		for _, c := range snap.Collections {
			if c.ID == id && !c.ReadOnly {
				return nil
			}
		}
	}
	if o, ok := snap.Organization(it.OrganizationID); ok && (o.Role == bitwarden.MemberOwner || o.Role == bitwarden.MemberAdmin) {
		return nil
	}
	return fmt.Errorf("%w: item %q", ErrReadOnly, it.Name)
}

func cloneItem(it *Item) Item {
	out := *it
	out.CollectionIDs = slices.Clone(it.CollectionIDs)
	out.URIs = slices.Clone(it.URIs)
	out.Fields = slices.Clone(it.Fields)
	out.PasswordHistory = slices.Clone(it.PasswordHistory)
	out.Attachments = slices.Clone(it.Attachments)
	if it.SSH != nil {
		ssh := *it.SSH
		out.SSH = &ssh
	}
	out.Card = cloneMap(it.Card)
	out.Identity = cloneMap(it.Identity)
	return out
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Trash moves an item to the trash.
func (v *Vault) Trash(ctx context.Context, ref ItemRef) (Item, error) {
	var target Item
	err := v.mutate(ctx, func(snap *Snapshot) error {
		it, err := snap.Item(ref)
		if err != nil {
			return err
		}
		if err := checkEditable(snap, it); err != nil {
			return err
		}
		target = *it
		return v.retry(func() error { return v.client.TrashCipher(ctx, it.ID) })
	})
	return target, err
}

// Delete destroys an item. Callers gate this behind an explicit setting.
func (v *Vault) Delete(ctx context.Context, ref ItemRef) (Item, error) {
	var target Item
	err := v.mutate(ctx, func(snap *Snapshot) error {
		it, err := snap.Item(ref)
		if err != nil {
			return err
		}
		if err := checkEditable(snap, it); err != nil {
			return err
		}
		target = *it
		return v.retry(func() error { return v.client.DeleteCipher(ctx, it.ID) })
	})
	return target, err
}

// Restore brings an item back from the trash.
func (v *Vault) Restore(ctx context.Context, ref ItemRef) (Item, error) {
	ref.Trash = true
	var target Item
	err := v.mutate(ctx, func(snap *Snapshot) error {
		it, err := snap.Item(ref)
		if err != nil {
			return err
		}
		target = *it
		return v.retry(func() error {
			_, err := v.client.RestoreCipher(ctx, it.ID)
			return err
		})
	})
	if err != nil {
		return Item{}, err
	}
	target.Deleted = nil
	return target, nil
}

// SetCollections replaces the collections an item is in. The new set must stay
// inside the item's organization.
func (v *Vault) SetCollections(ctx context.Context, ref ItemRef, collections []string) (Item, error) {
	var target Item
	err := v.mutate(ctx, func(snap *Snapshot) error {
		it, err := snap.Item(ref)
		if err != nil {
			return err
		}
		if it.OrganizationID == "" {
			return fmt.Errorf("%w: %q is in the personal vault, not in an organization", ErrInvalid, it.Name)
		}
		cols, err := resolveWritableIn(snap, it.OrganizationID, collections)
		if err != nil {
			return err
		}
		target = *it
		target.CollectionIDs = ids(cols)
		return v.retry(func() error { return v.client.SetCipherCollections(ctx, it.ID, ids(cols)) })
	})
	return target, err
}

// recordHistory keeps what the official clients keep when an item changes: the
// previous password, and "name: value" for every hidden field whose value
// changed or that was removed — newest first, five entries at most.
func recordHistory(current *Item, next *Item, now time.Time) {
	var added []PasswordChange
	if next.Password != current.Password && current.Password != "" {
		added = append(added, PasswordChange{Password: current.Password, Changed: now})
		stamp := bitwarden.FormatTime(now)
		next.passwordRevised = &stamp
	}
	for _, old := range current.Fields {
		if old.Kind != FieldHidden || old.Name == "" || old.Value == "" {
			continue
		}
		kept := slices.ContainsFunc(next.Fields, func(f Field) bool {
			return f.Kind == FieldHidden && f.Name == old.Name && f.Value == old.Value
		})
		if !kept {
			added = append(added, PasswordChange{Password: old.Name + ": " + old.Value, Changed: now})
		}
	}
	if len(added) == 0 {
		return
	}
	next.PasswordHistory = append(added, next.PasswordHistory...)
	if len(next.PasswordHistory) > passwordHistoryLimit {
		next.PasswordHistory = next.PasswordHistory[:passwordHistoryLimit]
	}
}
