package mcpserver

import (
	"sort"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

// The views below are the only shapes an item leaves this service in. None
// of them has a field that can hold a secret value.

type fieldView struct {
	Name  string `json:"name"`
	Kind  string `json:"kind" jsonschema:"text, hidden, boolean or linked; hidden fields are secret and their value is never shown"`
	Value string `json:"value,omitempty" jsonschema:"shown for text and boolean fields only"`
}

type attachmentView struct {
	ID       string `json:"id"`
	FileName string `json:"file_name"`
	Size     int64  `json:"size_bytes"`
}

type itemSummary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type" jsonschema:"login, note, card, identity or ssh_key"`
	Collections []string `json:"collections"`
	Username    string   `json:"username,omitempty"`
	URIs        []string `json:"uris,omitempty"`
	Secrets     []string `json:"secrets" jsonschema:"names of the secret values the item holds, as get_secret and issue_value_link accept them: password, totp, notes (secure notes), ssh_private_key, field:<name>, card:<name>, identity:<name>"`
	Attachments int      `json:"attachments,omitempty"`
	Expires     string   `json:"expires,omitempty" jsonschema:"expiry date from the configured custom field"`
	Revised     string   `json:"revised"`
	Trashed     bool     `json:"trashed,omitempty"`
}

type itemDetail struct {
	itemSummary
	Notes           string            `json:"notes,omitempty" jsonschema:"description of the item; absent for secure notes, whose text is their secret"`
	Fields          []fieldView       `json:"fields,omitempty"`
	AttachmentList  []attachmentView  `json:"attachment_files,omitempty"`
	PasswordChanges []string          `json:"password_changes,omitempty" jsonschema:"dates of previous passwords kept in the history, newest first"`
	SSHPublicKey    string            `json:"ssh_public_key,omitempty"`
	SSHFingerprint  string            `json:"ssh_fingerprint,omitempty"`
	Card            map[string]string `json:"card,omitempty" jsonschema:"non-secret card details; the number is shown by its last four digits"`
	Identity        map[string]string `json:"identity,omitempty" jsonschema:"non-secret identity details"`
	Fingerprints    map[string]string `json:"fingerprints" jsonschema:"keyed digest per secret value; equal fingerprints mean equal values within this account"`
	Reprompt        bool              `json:"reprompt,omitempty" jsonschema:"a human marked this item as needing master-password re-prompt"`
	Created         string            `json:"created"`
}

func formatTime(t time.Time, zone *time.Location) string {
	if t.IsZero() {
		return ""
	}
	return t.In(zone).Format(time.RFC3339)
}

func secretNames(it *vault.Item) []string {
	out := []string{}
	for _, v := range it.Values() {
		if v.Secret {
			out = append(out, v.Field)
		}
	}
	return out
}

func summarize(snap *vault.Snapshot, it *vault.Item, cfg *config.Config) itemSummary {
	s := itemSummary{
		ID:          it.ID,
		Name:        it.Name,
		Type:        string(it.Type),
		Collections: snap.CollectionNames(it.CollectionIDs),
		Username:    it.Username,
		Secrets:     secretNames(it),
		Attachments: len(it.Attachments),
		Revised:     formatTime(it.Revised, cfg.Location),
		Trashed:     it.Deleted != nil,
	}
	for _, u := range it.URIs {
		s.URIs = append(s.URIs, u.URI)
	}
	if cfg.Checks.ExpiryField != "" {
		if at, ok, err := it.Expiry(cfg.Checks.ExpiryField, cfg.Location); err == nil && ok {
			s.Expires = at.In(cfg.Location).Format(time.DateOnly)
		}
	}
	return s
}

func detail(snap *vault.Snapshot, it *vault.Item, cfg *config.Config) itemDetail {
	d := itemDetail{
		itemSummary:  summarize(snap, it, cfg),
		Fingerprints: map[string]string{},
		Reprompt:     it.Reprompt != 0,
		Created:      formatTime(it.Created, cfg.Location),
	}
	if it.Type != vault.TypeNote {
		d.Notes = it.Notes
	}
	for _, f := range it.Fields {
		fv := fieldView{Name: f.Name, Kind: string(f.Kind)}
		if f.Kind == vault.FieldText || f.Kind == vault.FieldBoolean {
			fv.Value = f.Value
		}
		d.Fields = append(d.Fields, fv)
	}
	for _, a := range it.Attachments {
		d.AttachmentList = append(d.AttachmentList, attachmentView{ID: a.ID, FileName: a.FileName, Size: a.Size})
	}
	for _, h := range it.PasswordHistory {
		d.PasswordChanges = append(d.PasswordChanges, formatTime(h.Changed, cfg.Location))
	}
	if it.SSH != nil {
		d.SSHPublicKey, d.SSHFingerprint = it.SSH.Public, it.SSH.Fingerprint
	}
	if len(it.Card) > 0 {
		d.Card = map[string]string{}
		for k, v := range it.Card {
			switch k {
			case "code":
			case "number":
				if len(v) >= 4 {
					d.Card["number_last4"] = v[len(v)-4:]
				}
			default:
				d.Card[k] = v
			}
		}
	}
	if len(it.Identity) > 0 {
		d.Identity = map[string]string{}
		for k, v := range it.Identity {
			if !vault.IsSecretIdentityField(k) {
				d.Identity[k] = v
			}
		}
	}
	// A secret the account may not view gets no fingerprint: comparing
	// fingerprints would tell which other item holds it.
	for _, v := range it.Values() {
		if v.Secret && it.Viewable {
			d.Fingerprints[v.Field] = snap.Fingerprint(v.Value)
		}
	}
	return d
}

type collectionView struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Items         int                `json:"items"`
	ReadOnly      bool               `json:"read_only,omitempty"`
	HidePasswords bool               `json:"hide_passwords,omitempty"`
	Manage        bool               `json:"manage,omitempty"`
	Members       []memberAccessView `json:"members,omitempty" jsonschema:"admin mode only: who has access and how"`
}

type memberAccessView struct {
	Member        string `json:"member" jsonschema:"member email"`
	ReadOnly      bool   `json:"read_only,omitempty"`
	HidePasswords bool   `json:"hide_passwords,omitempty"`
	Manage        bool   `json:"manage,omitempty"`
}

func countItems(snap *vault.Snapshot, collectionID string) int {
	n := 0
	for i := range snap.Items {
		it := &snap.Items[i]
		if it.Deleted != nil {
			continue
		}
		for _, id := range it.CollectionIDs {
			if id == collectionID {
				n++
				break
			}
		}
	}
	return n
}

func sortSummaries(s []itemSummary) {
	sort.SliceStable(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}
