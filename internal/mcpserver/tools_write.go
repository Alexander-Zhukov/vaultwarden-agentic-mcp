package mcpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/generate"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

type fieldInput struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Kind  string `json:"kind,omitempty" jsonschema:"text (default), hidden (secret, never shown) or boolean"`
}

type generateInput struct {
	Length    int  `json:"length,omitempty" jsonschema:"12 to 256, default 32"`
	NoUpper   bool `json:"no_upper,omitempty"`
	NoDigits  bool `json:"no_digits,omitempty"`
	NoSymbols bool `json:"no_symbols,omitempty" jsonschema:"leave symbols out, for systems that reject them"`
}

func (g *generateInput) password() (string, error) {
	length := g.Length
	if length == 0 {
		length = 32
	}
	p, err := generate.Password(generate.Policy{Length: length, NoUpper: g.NoUpper, NoDigits: g.NoDigits, NoSymbols: g.NoSymbols})
	if err != nil {
		return "", fmt.Errorf("%w: %w", vault.ErrInvalid, err)
	}
	return p, nil
}

// toFields validates custom fields. An omitted kind stays empty here: a new
// field becomes text, an existing one keeps its kind — so updating the value
// of a hidden field never turns it into one get_item shows.
func toFields(in []fieldInput) ([]vault.Field, error) {
	out := make([]vault.Field, 0, len(in))
	for _, f := range in {
		kind := vault.FieldKind(f.Kind)
		switch kind {
		case "", vault.FieldText, vault.FieldHidden, vault.FieldBoolean:
		default:
			return nil, fmt.Errorf("%w: field %q: kind must be text, hidden or boolean", vault.ErrInvalid, f.Name)
		}
		if strings.TrimSpace(f.Name) == "" {
			return nil, fmt.Errorf("%w: a custom field needs a name", vault.ErrInvalid)
		}
		out = append(out, vault.Field{Name: f.Name, Value: f.Value, Kind: kind})
	}
	return out, nil
}

// setField replaces a field by name or appends it. A field without a kind
// keeps the kind of the one it replaces, or becomes text.
func setField(fields []vault.Field, f vault.Field) []vault.Field {
	for i := range fields {
		if fields[i].Name == f.Name {
			if f.Kind == "" {
				f.Kind = fields[i].Kind
			}
			fields[i] = f
			return fields
		}
	}
	if f.Kind == "" {
		f.Kind = vault.FieldText
	}
	return append(fields, f)
}

// loginOnly refuses login fields on another kind of item instead of dropping
// them silently.
func loginOnly(itemType vault.ItemType, username, password, totp bool, uris int) error {
	if itemType == vault.TypeLogin {
		return nil
	}
	if username || password || totp || uris > 0 {
		return fmt.Errorf("%w: username, password, totp and uris belong to login items, not %s", vault.ErrInvalid, itemType)
	}
	return nil
}

type writeOutput struct {
	Item      itemSummary `json:"item"`
	Generated bool        `json:"generated_password,omitempty" jsonschema:"a password was generated and stored; it is not shown — use issue_value_link or share_with_human to hand it on"`
	UploadURL string      `json:"upload_url,omitempty" jsonschema:"one-time URL through which the secret is supplied, when upload was requested"`
	Warnings  []string    `json:"warnings,omitempty"`
}

// notesWarnings reports a convention the new notes miss, without refusing
// the write: the convention belongs to the deployment.
func (s *server) notesWarnings(notes string, itemType vault.ItemType) []string {
	if itemType == vault.TypeNote {
		return nil
	}
	it := &vault.Item{Notes: notes, Type: itemType}
	var out []string
	for _, i := range (&vault.Snapshot{}).Check([]*vault.Item{it}, vault.CheckRules{NotesPrefixes: s.Config.Checks.NotesPrefixes, Zone: s.Config.Location}, s.Clock()) {
		if i.Kind == vault.IssueNotesFormat {
			out = append(out, i.Detail)
		}
	}
	return out
}

func (s *server) registerWrite(srv *mcp.Server) {
	cfg := s.Config

	type createInput struct {
		Collections      []string          `json:"collections" jsonschema:"collection names or ids the item goes into; at least one"`
		Name             string            `json:"name" jsonschema:"item name; must be unique within its collections"`
		Type             string            `json:"type,omitempty" jsonschema:"login (default), note, ssh_key, card or identity"`
		Notes            string            `json:"notes,omitempty" jsonschema:"description of the secret; for a note item, the secret text itself"`
		Username         string            `json:"username,omitempty"`
		Password         string            `json:"password,omitempty" jsonschema:"a value you already hold; prefer generate_password or upload so the value does not pass through this conversation"`
		GeneratePassword *generateInput    `json:"generate_password,omitempty" jsonschema:"generate the password server-side; it is stored and never shown"`
		Upload           bool              `json:"upload,omitempty" jsonschema:"create the item without a value and return a one-time URL through which a human or program supplies it (password for logins, ssh_private_key for ssh_key items)"`
		TOTP             string            `json:"totp,omitempty" jsonschema:"TOTP seed or otpauth:// URI"`
		URIs             []string          `json:"uris,omitempty"`
		Fields           []fieldInput      `json:"fields,omitempty"`
		Expires          string            `json:"expires,omitempty" jsonschema:"expiry date YYYY-MM-DD, stored in the configured expiry field"`
		SSHPrivateKey    string            `json:"ssh_private_key,omitempty" jsonschema:"for ssh_key items; prefer upload"`
		SSHPublicKey     string            `json:"ssh_public_key,omitempty"`
		SSHFingerprint   string            `json:"ssh_fingerprint,omitempty"`
		Card             map[string]string `json:"card,omitempty" jsonschema:"for card items: cardholder_name, brand, number, exp_month, exp_year, code"`
		Identity         map[string]string `json:"identity,omitempty" jsonschema:"for identity items: title, first_name, middle_name, last_name, address1-3, city, state, postal_code, country, company, email, phone, ssn, username, passport_number, license_number"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "create_item",
		Description: "Create an item directly in its collections. The response never contains the secret. " +
			"To store a new credential without it passing through this conversation, set generate_password " +
			"(a random password made server-side) or upload (a one-time URL for a human or program to supply it).",
	}, func(ctx context.Context, c *call, in createInput) (writeOutput, error) {
		if err := c.requireWrite(); err != nil {
			return writeOutput{}, err
		}
		collections, err := c.collectionIDs(ctx, in.Collections)
		if err != nil {
			return writeOutput{}, err
		}
		itemType := vault.TypeLogin
		if in.Type != "" {
			t, err := vault.ParseItemType(in.Type)
			if err != nil {
				return writeOutput{}, err
			}
			itemType = t
		}
		sources := 0
		for _, set := range []bool{in.Password != "", in.GeneratePassword != nil, in.Upload} {
			if set {
				sources++
			}
		}
		if sources > 1 {
			return writeOutput{}, fmt.Errorf("%w: give at most one of password, generate_password and upload", vault.ErrInvalid)
		}
		if err := loginOnly(itemType, in.Username != "", in.Password != "" || in.GeneratePassword != nil, in.TOTP != "", len(in.URIs)); err != nil {
			return writeOutput{}, err
		}
		if err := s.uniqueName(ctx, c, in.Name, collections, ""); err != nil {
			return writeOutput{}, err
		}
		fields, err := toFields(in.Fields)
		if err != nil {
			return writeOutput{}, err
		}
		for i := range fields {
			if fields[i].Kind == "" {
				fields[i].Kind = vault.FieldText
			}
		}
		if in.Expires != "" {
			if _, err := time.Parse(time.DateOnly, in.Expires); err != nil {
				return writeOutput{}, fmt.Errorf("%w: expires must be YYYY-MM-DD", vault.ErrInvalid)
			}
			fields = setField(fields, vault.Field{Name: cfg.Checks.ExpiryField, Value: in.Expires, Kind: vault.FieldText})
		}
		n := vault.NewItem{
			Collections: collections, Type: itemType, Name: in.Name, Notes: in.Notes,
			Username: in.Username, Password: in.Password, TOTP: in.TOTP, Fields: fields,
			Card: in.Card, Identity: in.Identity,
		}
		for _, u := range in.URIs {
			n.URIs = append(n.URIs, vault.URI{URI: u})
		}
		if itemType == vault.TypeSSHKey {
			n.SSH = &vault.SSHKey{Private: in.SSHPrivateKey, Public: in.SSHPublicKey, Fingerprint: in.SSHFingerprint}
		}
		out := writeOutput{Warnings: s.notesWarnings(in.Notes, itemType)}
		if in.GeneratePassword != nil {
			if itemType != vault.TypeLogin {
				return writeOutput{}, fmt.Errorf("%w: generate_password is for login items", vault.ErrInvalid)
			}
			if n.Password, err = in.GeneratePassword.password(); err != nil {
				return writeOutput{}, err
			}
			out.Generated = true
		}
		uploadField := ""
		if in.Upload {
			switch itemType {
			case vault.TypeLogin:
				uploadField = "password"
			case vault.TypeSSHKey:
				uploadField = "ssh_private_key"
			case vault.TypeNote:
				uploadField = "notes"
			default:
				return writeOutput{}, fmt.Errorf("%w: upload is for login, ssh_key and note items", vault.ErrInvalid)
			}
			if !cfg.Links.Enabled() {
				return writeOutput{}, fmt.Errorf("%w: one-time links", errDisabled)
			}
		}
		created, err := s.Vault.Create(ctx, n)
		if err != nil {
			return writeOutput{}, err
		}
		c.touched(&created)
		c.mutated("create")
		snap, err := c.snapshot(ctx)
		if err != nil {
			return writeOutput{}, err
		}
		out.Item = summarize(snap, &created, cfg)
		if uploadField != "" {
			token, err := s.Links.Issue(links.Link{
				Kind: links.KindUpload, ItemID: created.ID, Field: uploadField,
				Client: c.principal.Name, Collections: c.principal.Collections,
				Expires: s.Clock().Add(cfg.Links.UploadTTL),
			})
			if err != nil {
				return writeOutput{}, err
			}
			s.Metrics.Links.WithLabelValues(string(links.KindUpload), "issued").Inc()
			out.UploadURL = cfg.Links.PublicURL + "/v1/upload/" + token
		}
		return out, nil
	})

	type updateInput struct {
		Item             string         `json:"item" jsonschema:"the item: its id, or its name"`
		Collection       string         `json:"collection,omitempty" jsonschema:"optional collection name or id, to disambiguate a name"`
		Name             *string        `json:"name,omitempty" jsonschema:"new name"`
		Notes            *string        `json:"notes,omitempty" jsonschema:"new notes, replacing the old ones"`
		Username         *string        `json:"username,omitempty"`
		Password         *string        `json:"password,omitempty" jsonschema:"new password; the previous one moves to the password history. Prefer generate_password"`
		GeneratePassword *generateInput `json:"generate_password,omitempty" jsonschema:"rotate: generate a new password server-side; the old one moves to the history, the new one is never shown"`
		TOTP             *string        `json:"totp,omitempty" jsonschema:"new TOTP seed or otpauth:// URI; empty string removes it"`
		URIs             []string       `json:"uris,omitempty" jsonschema:"replaces every address of the login"`
		SetFields        []fieldInput   `json:"set_fields,omitempty" jsonschema:"custom fields to add or replace, by name"`
		RemoveFields     []string       `json:"remove_fields,omitempty" jsonschema:"custom field names to remove"`
		Expires          *string        `json:"expires,omitempty" jsonschema:"new expiry date YYYY-MM-DD; empty string removes it"`
		SSHPublicKey     *string        `json:"ssh_public_key,omitempty"`
		SSHFingerprint   *string        `json:"ssh_fingerprint,omitempty"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "update_item",
		Description: "Change an item. Only the fields you pass change. A new password pushes the previous one into " +
			"the item's password history, so a rotation can be undone by hand. Use generate_password to rotate " +
			"without the new value passing through this conversation; the update is refused if the item changed " +
			"elsewhere since it was read.",
	}, func(ctx context.Context, c *call, in updateInput) (writeOutput, error) {
		if err := c.requireWrite(); err != nil {
			return writeOutput{}, err
		}
		_, it, err := c.item(ctx, in.Item, in.Collection, false)
		if err != nil {
			return writeOutput{}, err
		}
		if in.Password != nil && in.GeneratePassword != nil {
			return writeOutput{}, fmt.Errorf("%w: give password or generate_password, not both", vault.ErrInvalid)
		}
		if err := loginOnly(it.Type, in.Username != nil, in.Password != nil || in.GeneratePassword != nil, in.TOTP != nil, len(in.URIs)); err != nil {
			return writeOutput{}, err
		}
		if in.Name != nil && *in.Name != it.Name {
			if err := s.uniqueName(ctx, c, *in.Name, it.CollectionIDs, it.ID); err != nil {
				return writeOutput{}, err
			}
		}
		setFields, err := toFields(in.SetFields)
		if err != nil {
			return writeOutput{}, err
		}
		if in.Expires != nil && *in.Expires != "" {
			if _, err := time.Parse(time.DateOnly, *in.Expires); err != nil {
				return writeOutput{}, fmt.Errorf("%w: expires must be YYYY-MM-DD", vault.ErrInvalid)
			}
		}
		out := writeOutput{}
		var generated string
		if in.GeneratePassword != nil {
			if it.Type != vault.TypeLogin {
				return writeOutput{}, fmt.Errorf("%w: generate_password is for login items", vault.ErrInvalid)
			}
			if generated, err = in.GeneratePassword.password(); err != nil {
				return writeOutput{}, err
			}
			out.Generated = true
		}
		var changed []string
		updated, err := s.Vault.Update(ctx, vault.ItemRef{Ref: it.ID}, func(next *vault.Item) error {
			if in.Name != nil {
				next.Name, changed = *in.Name, append(changed, "name")
			}
			if in.Notes != nil {
				next.Notes, changed = *in.Notes, append(changed, "notes")
			}
			if in.Username != nil {
				next.Username, changed = *in.Username, append(changed, "username")
			}
			if in.Password != nil {
				next.Password, changed = *in.Password, append(changed, "password")
			}
			if generated != "" {
				next.Password, changed = generated, append(changed, "password")
			}
			if in.TOTP != nil {
				next.TOTP, changed = *in.TOTP, append(changed, "totp")
			}
			if in.URIs != nil {
				next.URIs = nil
				for _, u := range in.URIs {
					next.URIs = append(next.URIs, vault.URI{URI: u})
				}
				changed = append(changed, "uris")
			}
			for _, f := range setFields {
				next.Fields = setField(next.Fields, f)
				changed = append(changed, "field:"+f.Name)
			}
			if len(in.RemoveFields) > 0 {
				next.Fields = slices.DeleteFunc(next.Fields, func(f vault.Field) bool { return slices.Contains(in.RemoveFields, f.Name) })
				changed = append(changed, "remove_fields")
			}
			if in.Expires != nil {
				if *in.Expires == "" {
					next.Fields = slices.DeleteFunc(next.Fields, func(f vault.Field) bool { return f.Name == cfg.Checks.ExpiryField })
				} else {
					next.Fields = setField(next.Fields, vault.Field{Name: cfg.Checks.ExpiryField, Value: *in.Expires, Kind: vault.FieldText})
				}
				changed = append(changed, "expires")
			}
			if in.SSHPublicKey != nil || in.SSHFingerprint != nil {
				if next.SSH == nil {
					next.SSH = &vault.SSHKey{}
				}
				if in.SSHPublicKey != nil {
					next.SSH.Public = *in.SSHPublicKey
				}
				if in.SSHFingerprint != nil {
					next.SSH.Fingerprint = *in.SSHFingerprint
				}
				changed = append(changed, "ssh_public_key")
			}
			if len(changed) == 0 {
				return fmt.Errorf("%w: nothing to change", vault.ErrInvalid)
			}
			return nil
		})
		if err != nil {
			return writeOutput{}, err
		}
		c.mutated("update")
		c.note(slog.Any("changed", changed))
		snap, err := c.snapshot(ctx)
		if err != nil {
			return writeOutput{}, err
		}
		out.Item = summarize(snap, &updated, cfg)
		if in.Notes != nil {
			out.Warnings = s.notesWarnings(*in.Notes, updated.Type)
		}
		return out, nil
	})

	type deleteInput struct {
		Item       string `json:"item" jsonschema:"the item: its id, or its name"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
		Permanent  bool   `json:"permanent,omitempty" jsonschema:"destroy instead of moving to the trash; only where the instance allows it. Trashed items can be restored"`
	}
	type deleteOutput struct {
		Item      string `json:"item"`
		ID        string `json:"id"`
		Permanent bool   `json:"permanent"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "delete_item",
		Description: "Move an item to the trash, from which restore_item brings it back. Permanent deletion exists only where the instance enables it.",
	}, func(ctx context.Context, c *call, in deleteInput) (deleteOutput, error) {
		if err := c.requireWrite(); err != nil {
			return deleteOutput{}, err
		}
		if in.Permanent && !cfg.Caps.AllowPermanentDelete {
			return deleteOutput{}, fmt.Errorf("%w: permanent deletion; the item can be moved to the trash instead", errDisabled)
		}
		it, err := s.deleteTarget(ctx, c, in.Item, in.Collection, in.Permanent)
		if err != nil {
			return deleteOutput{}, err
		}
		ref := vault.ItemRef{Ref: it.ID}
		kind := "trash"
		if in.Permanent {
			_, err = s.Vault.Delete(ctx, ref)
			kind = "delete"
		} else {
			_, err = s.Vault.Trash(ctx, ref)
		}
		if err != nil {
			return deleteOutput{}, err
		}
		c.mutated(kind)
		s.Links.Revoke(it.ID)
		return deleteOutput{Item: it.Name, ID: it.ID, Permanent: in.Permanent}, nil
	})

	type restoreInput struct {
		Item       string `json:"item" jsonschema:"the trashed item: its id, or its name"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "restore_item",
		Description: "Bring an item back from the trash.",
	}, func(ctx context.Context, c *call, in restoreInput) (writeOutput, error) {
		if err := c.requireWrite(); err != nil {
			return writeOutput{}, err
		}
		_, it, err := c.item(ctx, in.Item, in.Collection, true)
		if err != nil {
			return writeOutput{}, err
		}
		restored, err := s.Vault.Restore(ctx, vault.ItemRef{Ref: it.ID})
		if err != nil {
			return writeOutput{}, err
		}
		c.mutated("restore")
		snap, err := c.snapshot(ctx)
		if err != nil {
			return writeOutput{}, err
		}
		return writeOutput{Item: summarize(snap, &restored, cfg)}, nil
	})

	type addAttachmentInput struct {
		Item       string `json:"item" jsonschema:"the item: its id, or its name"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
		FileName   string `json:"file_name" jsonschema:"name the file is stored under"`
		Text       string `json:"text,omitempty" jsonschema:"file content as text"`
		Base64     string `json:"base64,omitempty" jsonschema:"file content, base64-encoded, for binary files"`
	}
	type attachmentOut struct {
		Item       string         `json:"item"`
		Attachment attachmentView `json:"attachment"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "add_attachment",
		Description: "Attach a file to an item, from text or base64 content you already hold. To store a file " +
			"without its content passing through this conversation, use request_value_upload with attachment set.",
	}, func(ctx context.Context, c *call, in addAttachmentInput) (attachmentOut, error) {
		if err := c.requireWrite(); err != nil {
			return attachmentOut{}, err
		}
		if (in.Text == "") == (in.Base64 == "") {
			return attachmentOut{}, fmt.Errorf("%w: give exactly one of text and base64", vault.ErrInvalid)
		}
		content := []byte(in.Text)
		if in.Base64 != "" {
			var err error
			if content, err = base64.StdEncoding.DecodeString(in.Base64); err != nil {
				return attachmentOut{}, fmt.Errorf("%w: base64 does not decode", vault.ErrInvalid)
			}
		}
		_, it, err := c.item(ctx, in.Item, in.Collection, false)
		if err != nil {
			return attachmentOut{}, err
		}
		att, err := s.Vault.AddAttachment(ctx, vault.ItemRef{Ref: it.ID}, in.FileName, content)
		if err != nil {
			return attachmentOut{}, err
		}
		c.mutated("add_attachment")
		c.note(slog.String("attachment", att.FileName))
		return attachmentOut{Item: it.Name, Attachment: attachmentView{ID: att.ID, FileName: att.FileName, Size: att.Size}}, nil
	})

	type deleteAttachmentInput struct {
		Item       string `json:"item" jsonschema:"the item: its id, or its name"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
		Attachment string `json:"attachment" jsonschema:"attachment id or file name"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "delete_attachment",
		Description: "Remove an attachment from an item. This cannot be undone: attachments do not go to the trash.",
	}, func(ctx context.Context, c *call, in deleteAttachmentInput) (attachmentOut, error) {
		if err := c.requireWrite(); err != nil {
			return attachmentOut{}, err
		}
		_, it, err := c.item(ctx, in.Item, in.Collection, false)
		if err != nil {
			return attachmentOut{}, err
		}
		att, err := s.Vault.DeleteAttachment(ctx, vault.ItemRef{Ref: it.ID}, in.Attachment)
		if err != nil {
			return attachmentOut{}, err
		}
		c.mutated("delete_attachment")
		c.note(slog.String("attachment", att.FileName))
		return attachmentOut{Item: it.Name, Attachment: attachmentView{ID: att.ID, FileName: att.FileName, Size: att.Size}}, nil
	})
}

// deleteTarget resolves the item a delete acts on. A permanent delete may
// target a trashed or a live item, and a name found in both places is
// ambiguous: destroying the wrong one cannot be undone.
func (s *server) deleteTarget(ctx context.Context, c *call, ref, collection string, permanent bool) (*vault.Item, error) {
	_, live, liveErr := c.item(ctx, ref, collection, false)
	if !permanent {
		return live, liveErr
	}
	if errors.Is(liveErr, vault.ErrAmbiguous) {
		return nil, liveErr
	}
	_, trashed, trashErr := c.item(ctx, ref, collection, true)
	switch {
	case liveErr == nil && trashErr == nil && live.ID != trashed.ID:
		return nil, fmt.Errorf("%w: %q names a live item (%s) and a trashed one (%s); pass the id", vault.ErrAmbiguous, ref, live.ID, trashed.ID)
	case trashErr == nil:
		return trashed, nil
	case errors.Is(trashErr, vault.ErrNotFound):
		return live, liveErr
	default:
		return nil, trashErr
	}
}

// uniqueName refuses a name already used by another live item in any of the
// given collections that this client can see, so that a name keeps resolving
// to exactly one item. self is the item being renamed, if any.
func (s *server) uniqueName(ctx context.Context, c *call, name string, collections []string, self string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: name is required", vault.ErrInvalid)
	}
	snap, err := c.snapshot(ctx)
	if err != nil {
		return err
	}
	for _, ref := range collections {
		col, err := snap.Collection(ref)
		if errors.Is(err, vault.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		it, err := snap.Item(vault.ItemRef{Ref: name, Collection: col.ID})
		switch {
		case err == nil && it.ID != self && strings.EqualFold(it.Name, name):
			return fmt.Errorf("%w: collection %q already has an item named %q (%s); update it instead", vault.ErrInvalid, col.Name, it.Name, it.ID)
		case errors.Is(err, vault.ErrAmbiguous):
			return fmt.Errorf("%w: collection %q already has several items named %q", vault.ErrInvalid, col.Name, name)
		}
	}
	return nil
}
