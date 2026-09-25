package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

type statusOutput struct {
	Account              string   `json:"account" jsonschema:"label of this instance"`
	Email                string   `json:"email" jsonschema:"the Vaultwarden account this instance acts as"`
	Mode                 string   `json:"mode" jsonschema:"consumer (items in visible collections) or admin (also organization management)"`
	Client               string   `json:"client" jsonschema:"who you are to this instance"`
	ClientReadOnly       bool     `json:"client_read_only,omitempty"`
	ClientCollections    []string `json:"client_collections,omitempty" jsonschema:"the collections this client is narrowed to; empty means every collection of the account"`
	Organizations        []string `json:"organizations"`
	Collections          []string `json:"collections"`
	Items                int      `json:"items"`
	Undecryptable        int      `json:"undecryptable_items,omitempty"`
	AllowReveal          bool     `json:"allow_reveal" jsonschema:"whether get_secret and get_attachment exist on this instance"`
	AllowWrite           bool     `json:"allow_write"`
	AllowPermanentDelete bool     `json:"allow_permanent_delete"`
	AllowShare           bool     `json:"allow_share" jsonschema:"whether share_with_human exists on this instance"`
	LinksEnabled         bool     `json:"links_enabled" jsonschema:"whether issue_value_link and request_value_upload exist"`
	LinkTTL              string   `json:"link_ttl,omitempty"`
	MaxAttachmentBytes   int64    `json:"max_attachment_bytes"`
	LastSync             string   `json:"last_sync"`
	Version              string   `json:"version"`
	UptimeSeconds        int      `json:"uptime_seconds"`
	Tools                []string `json:"tools"`
}

func (s *server) registerRead(srv *mcp.Server) {
	addTool(s, srv, &mcp.Tool{
		Name: "get_status",
		Description: "Report what this instance is: the account, the mode, which collections you can see, " +
			"and which capabilities are switched on (revealing values, writing, links). Call it first when unsure what is possible.",
	}, func(ctx context.Context, c *call, _ struct{}) (statusOutput, error) {
		snap, err := c.snapshot(ctx)
		if err != nil {
			return statusOutput{}, err
		}
		cfg := s.Config
		out := statusOutput{
			Account: cfg.Account, Email: snap.Email, Mode: string(cfg.Mode),
			Client: c.principal.Name, ClientReadOnly: c.principal.ReadOnly, ClientCollections: c.principal.Collections,
			Items: len(snap.Items), Undecryptable: len(snap.Broken),
			AllowReveal: cfg.Caps.AllowReveal, AllowWrite: cfg.Caps.AllowWrite && !c.principal.ReadOnly,
			AllowPermanentDelete: cfg.Caps.AllowPermanentDelete, LinksEnabled: cfg.Links.Enabled(),
			AllowShare:         cfg.Caps.AllowShare && cfg.Caps.AllowWrite,
			MaxAttachmentBytes: cfg.MaxAttachment, LastSync: formatTime(snap.At, cfg.Location),
			Version: s.Version, UptimeSeconds: int(s.Clock().Sub(s.StartedAt).Seconds()), Tools: s.registered,
		}
		if cfg.Links.Enabled() {
			out.LinkTTL = cfg.Links.TTL.String()
		}
		for _, o := range snap.Organizations {
			out.Organizations = append(out.Organizations, o.Name)
		}
		for _, col := range snap.Collections {
			out.Collections = append(out.Collections, col.Name)
		}
		return out, nil
	})

	type listCollectionsOutput struct {
		Collections []collectionView `json:"collections"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "list_collections",
		Description: "List the collections you can see with their item counts and your access. " +
			"In admin mode this lists every collection of the organization with its members.",
	}, func(ctx context.Context, c *call, _ struct{}) (listCollectionsOutput, error) {
		snap, err := c.snapshot(ctx)
		if err != nil {
			return listCollectionsOutput{}, err
		}
		out := listCollectionsOutput{Collections: []collectionView{}}
		if s.Config.Mode == config.ModeAdmin && c.principal.Unrestricted() {
			admin, err := s.Vault.Admin(ctx, s.Config.Organization)
			if err != nil {
				return listCollectionsOutput{}, err
			}
			cols, err := admin.Collections(ctx)
			if err != nil {
				return listCollectionsOutput{}, err
			}
			for _, col := range cols {
				v := collectionView{ID: col.ID, Name: col.Name, Items: col.Items}
				for _, m := range col.Members {
					v.Members = append(v.Members, memberAccessView{Member: m.Member, ReadOnly: m.ReadOnly, HidePasswords: m.HidePasswords, Manage: m.Manage})
				}
				out.Collections = append(out.Collections, v)
			}
			return out, nil
		}
		for _, col := range snap.Collections {
			out.Collections = append(out.Collections, collectionView{
				ID: col.ID, Name: col.Name, Items: countItems(snap, col.ID),
				ReadOnly: col.ReadOnly, HidePasswords: col.HidePasswords, Manage: col.Manage,
			})
		}
		return out, nil
	})

	type listInput struct {
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
		Type       string `json:"type,omitempty" jsonschema:"optional item type: login, note, card, identity or ssh_key"`
		Trash      bool   `json:"trash,omitempty" jsonschema:"true to list the trash instead"`
	}
	type listOutput struct {
		Items []itemSummary `json:"items"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "list_items",
		Description: "List items with their metadata — name, type, collections, username, addresses, which secret " +
			"values they hold, expiry — and never the values themselves.",
	}, func(ctx context.Context, c *call, in listInput) (listOutput, error) {
		snap, filter, err := c.filtered(ctx, in.Collection, in.Type, in.Trash)
		if err != nil {
			return listOutput{}, err
		}
		items, err := snap.ItemsMatching(filter)
		if err != nil {
			return listOutput{}, err
		}
		out := listOutput{Items: []itemSummary{}}
		for _, it := range items {
			out.Items = append(out.Items, summarize(snap, it, s.Config))
		}
		sortSummaries(out.Items)
		return out, nil
	})

	type searchInput struct {
		Query      string `json:"query" jsonschema:"words to find; every word must match somewhere in the item's name, username, addresses, notes, custom field names or non-secret field values, or attachment names"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
		Type       string `json:"type,omitempty" jsonschema:"optional item type: login, note, card, identity or ssh_key"`
		Trash      bool   `json:"trash,omitempty" jsonschema:"true to search the trash instead"`
	}
	type searchHit struct {
		itemSummary
		Matched []string `json:"matched" jsonschema:"where the words were found: name, username, uri, notes, field:<name> or attachment"`
	}
	type searchOutput struct {
		Items []searchHit `json:"items"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "search_items",
		Description: "Find items by what describes them, best matches first. Secret values are never searched " +
			"or returned here; to find which item holds a value you already have, use find_by_value.",
	}, func(ctx context.Context, c *call, in searchInput) (searchOutput, error) {
		snap, filter, err := c.filtered(ctx, in.Collection, in.Type, in.Trash)
		if err != nil {
			return searchOutput{}, err
		}
		matches, err := snap.Search(in.Query, filter)
		if err != nil {
			return searchOutput{}, err
		}
		out := searchOutput{Items: []searchHit{}}
		for _, m := range matches {
			out.Items = append(out.Items, searchHit{itemSummary: summarize(snap, m.Item, s.Config), Matched: m.Matched})
		}
		return out, nil
	})

	type getItemInput struct {
		Item       string `json:"item" jsonschema:"the item: its id, or its name; a name found in several collections is an error listing the ids"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id, to disambiguate a name"`
		Trash      bool   `json:"trash,omitempty" jsonschema:"true to look in the trash"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "get_item",
		Description: "Show everything about an item except its secret values: notes, custom fields (hidden ones by " +
			"name only), attachments, password change dates, the SSH public key, and a fingerprint per secret value.",
	}, func(ctx context.Context, c *call, in getItemInput) (itemDetail, error) {
		snap, it, err := c.item(ctx, in.Item, in.Collection, in.Trash)
		if err != nil {
			return itemDetail{}, err
		}
		return detail(snap, it, s.Config), nil
	})

	type findValueInput struct {
		Value      string `json:"value" jsonschema:"a value you already hold, at least 8 characters, e.g. a token found in a config file; compared exactly against every value of every item"`
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
	}
	type valueHit struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Collections []string `json:"collections"`
		Fields      []string `json:"fields" jsonschema:"where the value is stored in the item"`
	}
	type findValueOutput struct {
		Items []valueHit `json:"items"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "find_by_value",
		Description: "Tell which items hold a value you already have — to identify a leaked token, or to find " +
			"what to rotate. Only item names and field names come back.",
	}, func(ctx context.Context, c *call, in findValueInput) (findValueOutput, error) {
		if !s.searches.allow(c.principal.Name) {
			return findValueOutput{}, fmt.Errorf("%w: at most %d value searches a minute", vault.ErrInvalid, s.Config.Tuning.FindPerMinute)
		}
		snap, filter, err := c.filtered(ctx, in.Collection, "", false)
		if err != nil {
			return findValueOutput{}, err
		}
		found, err := snap.FindValue(in.Value, filter)
		if err != nil {
			return findValueOutput{}, err
		}
		out := findValueOutput{Items: []valueHit{}}
		for _, f := range found {
			out.Items = append(out.Items, valueHit{ID: f.Item.ID, Name: f.Item.Name, Collections: snap.CollectionNames(f.Item.CollectionIDs), Fields: f.Fields})
		}
		c.note(slog.Int("matches", len(out.Items)))
		return out, nil
	})

	type copiesOutput struct {
		Item   string     `json:"item"`
		Copies []valueHit `json:"copies" jsonschema:"other items holding one of this item's secret values; update them together when rotating"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "find_copies",
		Description: "List the other items that hold any secret value of this item, across every collection you can see.",
	}, func(ctx context.Context, c *call, in getItemInput) (copiesOutput, error) {
		snap, it, err := c.item(ctx, in.Item, in.Collection, false)
		if err != nil {
			return copiesOutput{}, err
		}
		out := copiesOutput{Item: it.Name, Copies: []valueHit{}}
		for _, m := range snap.Copies(it) {
			out.Copies = append(out.Copies, valueHit{ID: m.Item.ID, Name: m.Item.Name, Collections: snap.CollectionNames(m.Item.CollectionIDs), Fields: m.Fields})
		}
		return out, nil
	})

	type checkInput struct {
		Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id; all visible collections when empty"`
	}
	type issueView struct {
		ItemID string `json:"item_id"`
		Item   string `json:"item"`
		Kind   string `json:"kind" jsonschema:"notes_format, expired, expires_soon, bad_expiry, empty_secret, duplicate or undecryptable"`
		Detail string `json:"detail"`
	}
	type checkOutput struct {
		Checked int         `json:"checked"`
		Issues  []issueView `json:"issues"`
		Rules   []string    `json:"rules" jsonschema:"the checks that ran"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "check_items",
		Description: "Audit items: notes that do not follow the configured convention, credentials expired or " +
			"expiring soon, items without any secret value, the same secret stored in several items, and items " +
			"that cannot be decrypted.",
	}, func(ctx context.Context, c *call, in checkInput) (checkOutput, error) {
		snap, filter, err := c.filtered(ctx, in.Collection, "", false)
		if err != nil {
			return checkOutput{}, err
		}
		items, err := snap.ItemsMatching(filter)
		if err != nil {
			return checkOutput{}, err
		}
		rules := vault.CheckRules{
			NotesPrefixes: s.Config.Checks.NotesPrefixes,
			ExpiryField:   s.Config.Checks.ExpiryField,
			ExpiryHorizon: s.Config.Checks.ExpiryHorizon,
			Zone:          s.Config.Location,
		}
		out := checkOutput{Checked: len(items), Issues: []issueView{}, Rules: []string{"empty_secret", "duplicate", "undecryptable"}}
		if len(rules.NotesPrefixes) > 0 {
			out.Rules = append(out.Rules, fmt.Sprintf("notes_format %q", rules.NotesPrefixes))
		}
		if rules.ExpiryField != "" {
			out.Rules = append(out.Rules, fmt.Sprintf("expiry from field %q within %s", rules.ExpiryField, rules.ExpiryHorizon))
		}
		for _, i := range snap.Check(items, rules, s.Clock()) {
			out.Issues = append(out.Issues, issueView{ItemID: i.ItemID, Item: i.ItemName, Kind: string(i.Kind), Detail: i.Detail})
		}
		return out, nil
	})
}

func (c *call) filtered(ctx context.Context, collection, itemType string, trash bool) (*vault.Snapshot, vault.Filter, error) {
	snap, err := c.snapshot(ctx)
	if err != nil {
		return nil, vault.Filter{}, err
	}
	f := vault.Filter{Collection: collection, Trash: trash}
	if itemType != "" {
		t, err := vault.ParseItemType(itemType)
		if err != nil {
			return nil, vault.Filter{}, err
		}
		f.Type = t
	}
	return snap, f, nil
}

// clampTTL bounds a requested lifetime to the configured maximum.
func clampTTL(requested string, fallback, limit time.Duration) (time.Duration, error) {
	if requested == "" {
		return min(fallback, limit), nil
	}
	d, err := time.ParseDuration(requested)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%w: ttl %q is not a positive duration such as 90s or 10m", vault.ErrInvalid, requested)
	}
	return min(d, limit), nil
}
