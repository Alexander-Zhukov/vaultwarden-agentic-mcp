package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/totp"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

// fieldArg explains how a value inside an item is named.
const fieldArg = "which value: password, username, totp (returns the current one-time code, never the seed), " +
	"notes, ssh_private_key, ssh_public_key, field:<custom field name>, card:<number|code|...> or identity:<ssn|...>; " +
	"get_item lists what an item holds"

// valueOf returns the value a field names. For totp it is the code valid now,
// with how long it stays valid.
func valueOf(it *vault.Item, field string, now time.Time) (string, time.Duration, error) {
	if field == "" {
		field = "password"
	}
	v, ok := it.Secret(field)
	if !ok {
		return "", 0, fmt.Errorf("%w: item %q has no value %q", vault.ErrNotFound, it.Name, field)
	}
	if v.Secret && !it.Viewable {
		return "", 0, fmt.Errorf("%w: passwords of item %q are hidden from this account", vault.ErrReadOnly, it.Name)
	}
	// Re-prompt asks a human for their master password before showing the
	// item; an agent has none to give, so the item's secrets stay put.
	if v.Secret && it.Reprompt != 0 {
		return "", 0, fmt.Errorf("%w: item %q requires master-password re-prompt", vault.ErrReadOnly, it.Name)
	}
	if field == "totp" {
		p, err := totp.Parse(v.Value)
		if err != nil {
			return "", 0, fmt.Errorf("%w: item %q: %w", vault.ErrInvalid, it.Name, err)
		}
		code := p.At(now)
		return code.Code, code.ExpiresIn, nil
	}
	return v.Value, 0, nil
}

func (s *server) registerValues(srv *mcp.Server) {
	cfg := s.Config
	if cfg.Caps.AllowReveal {
		type secretInput struct {
			Item       string `json:"item" jsonschema:"the item: its id, or its name"`
			Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id, to disambiguate a name"`
			Field      string `json:"field,omitempty" jsonschema:"which value: password (default), username, totp (current one-time code, never the seed), notes, ssh_private_key, ssh_public_key, field:<custom field name>, card:<name> or identity:<name>"`
		}
		type secretOutput struct {
			Item      string `json:"item"`
			Field     string `json:"field"`
			Value     string `json:"value"`
			ExpiresIn int    `json:"expires_in_seconds,omitempty" jsonschema:"for totp: how long the code stays valid"`
		}
		addTool(s, srv, &mcp.Tool{
			Name: "get_secret",
			Description: "Return one secret value into this conversation. Prefer issue_value_link whenever the value " +
				"is going to a program: a value returned here stays in the transcript. " + fieldArg + ".",
		}, func(ctx context.Context, c *call, in secretInput) (secretOutput, error) {
			_, it, err := c.item(ctx, in.Item, in.Collection, false)
			if err != nil {
				return secretOutput{}, err
			}
			field := in.Field
			if field == "" {
				field = "password"
			}
			value, validFor, err := valueOf(it, field, s.Clock())
			if err != nil {
				return secretOutput{}, err
			}
			c.note(slog.String("field", field))
			return secretOutput{Item: it.Name, Field: field, Value: value, ExpiresIn: int(validFor.Seconds())}, nil
		})

		type attachmentInput struct {
			Item       string `json:"item" jsonschema:"the item: its id, or its name"`
			Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
			Attachment string `json:"attachment" jsonschema:"attachment id or file name, as get_item lists them"`
		}
		type attachmentOutput struct {
			FileName string `json:"file_name"`
			Size     int    `json:"size_bytes"`
			Text     string `json:"text,omitempty" jsonschema:"the content, when it is valid UTF-8"`
			Base64   string `json:"base64,omitempty" jsonschema:"the content, base64-encoded, when it is binary"`
		}
		addTool(s, srv, &mcp.Tool{
			Name: "get_attachment",
			Description: "Return an attachment's content into this conversation, as text or base64. Prefer " +
				"issue_value_link with attachment set when the file is going to disk or to a program.",
		}, func(ctx context.Context, c *call, in attachmentInput) (attachmentOutput, error) {
			_, it, err := c.item(ctx, in.Item, in.Collection, false)
			if err != nil {
				return attachmentOutput{}, err
			}
			if !it.Viewable || it.Reprompt != 0 {
				return attachmentOutput{}, fmt.Errorf("%w: item %q is hidden from this account or requires re-prompt", vault.ErrReadOnly, it.Name)
			}
			att, data, err := s.Vault.AttachmentContent(ctx, vault.ItemRef{Ref: it.ID}, in.Attachment)
			if err != nil {
				return attachmentOutput{}, err
			}
			c.note(slog.String("attachment", att.FileName))
			out := attachmentOutput{FileName: att.FileName, Size: len(data)}
			if utf8.Valid(data) {
				out.Text = string(data)
			} else {
				out.Base64 = base64.StdEncoding.EncodeToString(data)
			}
			return out, nil
		})
	}

	if cfg.Links.Enabled() {
		type linkInput struct {
			Item       string `json:"item" jsonschema:"the item: its id, or its name"`
			Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
			Field      string `json:"field,omitempty" jsonschema:"which value: password (default), username, totp (the code valid when the link is fetched), notes, ssh_private_key, ssh_public_key, field:<custom field name>, card:<name> or identity:<name>; ignored when attachment is set"`
			Attachment string `json:"attachment,omitempty" jsonschema:"attachment id or file name, to download a file instead of a value"`
			TTL        string `json:"ttl,omitempty" jsonschema:"how long the link lives, e.g. 60s or 5m; capped by the instance maximum"`
		}
		type linkOutput struct {
			URL     string `json:"url" jsonschema:"one-time URL; the first GET returns the raw value and kills the link"`
			Expires string `json:"expires"`
			Example string `json:"example" jsonschema:"how to use it without the value entering the conversation"`
		}
		addTool(s, srv, &mcp.Tool{
			Name: "issue_value_link",
			Description: "Get a one-time URL that returns one value (or one attachment) to whoever fetches it first, " +
				"then stops working. Use it inside the command that needs the value — " +
				"`curl -s <url> | gh auth login --with-token`, `curl -s -o ~/.ssh/key <url>`, " +
				"`TOKEN=$(curl -s <url>) some-cli` — so the value goes straight from the vault to the program and " +
				"never appears in this conversation. Do not fetch the link just to look at it. " + fieldArg + ".",
		}, func(ctx context.Context, c *call, in linkInput) (linkOutput, error) {
			_, it, err := c.item(ctx, in.Item, in.Collection, false)
			if err != nil {
				return linkOutput{}, err
			}
			ttl, err := clampTTL(in.TTL, cfg.Links.TTL, cfg.Links.TTL)
			if err != nil {
				return linkOutput{}, err
			}
			l := links.Link{ItemID: it.ID, Client: c.principal.Name, Collections: c.principal.Collections, Expires: s.Clock().Add(ttl)}
			useAs := func(url string) string { return "curl -sf " + url + " | <program reading the value from stdin>" }
			if in.Attachment != "" {
				if !it.Viewable || it.Reprompt != 0 {
					return linkOutput{}, fmt.Errorf("%w: item %q is hidden from this account or requires re-prompt", vault.ErrReadOnly, it.Name)
				}
				att, err := findAttachment(it, in.Attachment)
				if err != nil {
					return linkOutput{}, err
				}
				l.Kind, l.Attachment = links.KindAttachment, att.ID
				useAs = func(url string) string { return "curl -sf -o " + shellQuote(att.FileName) + " " + url }
				c.note(slog.String("attachment", att.FileName))
			} else {
				field := in.Field
				if field == "" {
					field = "password"
				}
				// Validate now, so a typo fails here and not in the program
				// that fetches the link.
				if _, _, err := valueOf(it, field, s.Clock()); err != nil {
					return linkOutput{}, err
				}
				l.Kind, l.Field = links.KindValue, field
				c.note(slog.String("field", field))
			}
			token, err := s.Links.Issue(l)
			if err != nil {
				return linkOutput{}, err
			}
			s.Metrics.Links.WithLabelValues(string(l.Kind), "issued").Inc()
			url := cfg.Links.PublicURL + "/v1/links/" + token
			return linkOutput{URL: url, Expires: formatTime(l.Expires, cfg.Location), Example: useAs(url)}, nil
		})
	}

	if cfg.Links.Enabled() && cfg.Caps.AllowWrite {
		type uploadInput struct {
			Item       string `json:"item" jsonschema:"the item that receives the value: its id, or its name; create it first with create_item if it does not exist"`
			Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
			Field      string `json:"field,omitempty" jsonschema:"where the value goes: password (default, login items), totp (a seed or otpauth:// URI, login items), ssh_private_key (ssh_key items), notes (note items, whose text is their secret), or field:<name> (stored as a hidden custom field, created if missing)"`
			Attachment string `json:"attachment,omitempty" jsonschema:"store an uploaded file as an attachment with this file name, instead of a value"`
			TTL        string `json:"ttl,omitempty" jsonschema:"how long the link lives, e.g. 10m or 1h; capped by the instance maximum"`
		}
		type uploadOutput struct {
			URL     string `json:"url" jsonschema:"one-time URL: a human opens it in a browser and pastes the value; a program sends it with curl"`
			Expires string `json:"expires"`
			Curl    string `json:"curl" jsonschema:"how a program sends the value without it entering the conversation"`
		}
		addTool(s, srv, &mcp.Tool{
			Name: "request_value_upload",
			Description: "Get a one-time URL through which a human or a program puts a secret into an item, so the " +
				"secret is never pasted into this conversation. Give the URL to the human (it opens a form), or " +
				"have a program send the value with curl. The link works once.",
		}, func(ctx context.Context, c *call, in uploadInput) (uploadOutput, error) {
			if err := c.requireWrite(); err != nil {
				return uploadOutput{}, err
			}
			_, it, err := c.item(ctx, in.Item, in.Collection, false)
			if err != nil {
				return uploadOutput{}, err
			}
			ttl, err := clampTTL(in.TTL, cfg.Links.UploadTTL, cfg.Links.UploadTTL)
			if err != nil {
				return uploadOutput{}, err
			}
			l := links.Link{Kind: links.KindUpload, ItemID: it.ID, Client: c.principal.Name, Collections: c.principal.Collections, Expires: s.Clock().Add(ttl)}
			if in.Attachment != "" {
				l.Attachment = in.Attachment
			} else {
				field := in.Field
				if field == "" {
					field = "password"
				}
				if err := uploadableField(it, field); err != nil {
					return uploadOutput{}, err
				}
				l.Field = field
			}
			token, err := s.Links.Issue(l)
			if err != nil {
				return uploadOutput{}, err
			}
			s.Metrics.Links.WithLabelValues(string(l.Kind), "issued").Inc()
			c.note(slog.String("field", l.Field), slog.String("attachment", l.Attachment))
			url := cfg.Links.PublicURL + "/v1/upload/" + token
			curl := "printf %s \"$VALUE\" | curl -sf -X PUT --data-binary @- " + url
			if l.Attachment != "" {
				curl = "curl -sf -X PUT --data-binary @<file> " + url
			}
			return uploadOutput{URL: url, Expires: formatTime(l.Expires, cfg.Location), Curl: curl}, nil
		})

	}
}

// registerShare adds the Send tools. They are a switch of their own: a Send
// link hands a value to whoever holds the URL.
func (s *server) registerShare(srv *mcp.Server) {
	cfg := s.Config
	{
		type shareInput struct {
			Item       string `json:"item" jsonschema:"the item: its id, or its name"`
			Collection string `json:"collection,omitempty" jsonschema:"optional collection name or id"`
			Field      string `json:"field,omitempty" jsonschema:"which value: password (default), username, notes, ssh_private_key, ssh_public_key, field:<name>, card:<name> or identity:<name>"`
			ExpiresIn  string `json:"expires_in,omitempty" jsonschema:"how long the link works, e.g. 1h or 24h; capped by the instance maximum"`
			MaxAccess  int    `json:"max_access,omitempty" jsonschema:"how many times the link may be opened; default 1, at most 10"`
		}
		type shareOutput struct {
			URL       string `json:"url" jsonschema:"a Bitwarden Send link for a human; it opens in the web vault"`
			ShareID   string `json:"share_id" jsonschema:"pass to revoke_share to kill the link early"`
			Expires   string `json:"expires"`
			MaxAccess int    `json:"max_access"`
		}
		addTool(s, srv, &mcp.Tool{
			Name: "share_with_human",
			Description: "Create a Bitwarden Send link that shows one value to a human in the web vault, then " +
				"expires. Give the human the link; the value itself never enters this conversation.",
		}, func(ctx context.Context, c *call, in shareInput) (shareOutput, error) {
			if err := c.requireWrite(); err != nil {
				return shareOutput{}, err
			}
			_, it, err := c.item(ctx, in.Item, in.Collection, false)
			if err != nil {
				return shareOutput{}, err
			}
			field := in.Field
			if field == "" {
				field = "password"
			}
			if field == "totp" {
				return shareOutput{}, fmt.Errorf("%w: a one-time code expires before a human opens the link", vault.ErrInvalid)
			}
			value, _, err := valueOf(it, field, s.Clock())
			if err != nil {
				return shareOutput{}, err
			}
			ttl, err := clampTTL(in.ExpiresIn, cfg.ShareTTL, cfg.MaxShareTTL)
			if err != nil {
				return shareOutput{}, err
			}
			maxAccess := in.MaxAccess
			if maxAccess <= 0 {
				maxAccess = 1
			}
			if maxAccess > 10 {
				return shareOutput{}, fmt.Errorf("%w: max_access is at most 10", vault.ErrInvalid)
			}
			info, url, err := s.Vault.CreateSend(ctx, vault.NewSend{
				Name: it.Name + " / " + field, Text: value, Expires: s.Clock().Add(ttl), MaxAccess: &maxAccess,
			}, cfg.Vaultwarden.WebURL)
			if err != nil {
				return shareOutput{}, err
			}
			s.shares.add(info.ID, c.principal.Name)
			c.mutated("share")
			c.note(slog.String("field", field), slog.String("share_id", info.ID))
			return shareOutput{URL: url, ShareID: info.ID, Expires: formatTime(s.Clock().Add(ttl), cfg.Location), MaxAccess: maxAccess}, nil
		})

		type revokeInput struct {
			ShareID string `json:"share_id" jsonschema:"the id share_with_human returned"`
		}
		type revokeOutput struct {
			Revoked string `json:"revoked"`
		}
		addTool(s, srv, &mcp.Tool{
			Name:        "revoke_share",
			Description: "Kill a share link created by share_with_human before it expires.",
		}, func(ctx context.Context, c *call, in revokeInput) (revokeOutput, error) {
			if err := c.requireWrite(); err != nil {
				return revokeOutput{}, err
			}
			if strings.TrimSpace(in.ShareID) == "" {
				return revokeOutput{}, fmt.Errorf("%w: share_id is required", vault.ErrInvalid)
			}
			// Only a share this client created in this process: the account
			// may hold Sends of humans and of other clients.
			if !s.shares.take(in.ShareID, c.principal.Name) {
				return revokeOutput{}, fmt.Errorf("%w: share %q was not created by this client", vault.ErrNotFound, in.ShareID)
			}
			if err := s.Vault.DeleteSend(ctx, in.ShareID); err != nil {
				s.shares.add(in.ShareID, c.principal.Name)
				return revokeOutput{}, err
			}
			c.mutated("revoke_share")
			c.note(slog.String("share_id", in.ShareID))
			return revokeOutput{Revoked: in.ShareID}, nil
		})
	}
}

// uploadableField checks that an upload can land in a field.
func uploadableField(it *vault.Item, field string) error {
	switch {
	case field == "password" || field == "totp":
		if it.Type != vault.TypeLogin {
			return fmt.Errorf("%w: %s belongs to login items; %q is a %s", vault.ErrInvalid, field, it.Name, it.Type)
		}
	case field == "ssh_private_key":
		if it.Type != vault.TypeSSHKey {
			return fmt.Errorf("%w: ssh_private_key belongs to ssh_key items; %q is a %s", vault.ErrInvalid, it.Name, it.Type)
		}
	case field == "notes":
		// The notes of any other item are description, shown by get_item.
		if it.Type != vault.TypeNote {
			return fmt.Errorf("%w: notes hold a secret only on note items; %q is a %s — use field:<name>", vault.ErrInvalid, it.Name, it.Type)
		}
	case strings.HasPrefix(field, "field:") && len(field) > len("field:"):
	default:
		return fmt.Errorf("%w: cannot upload into %q; use password, totp, notes, ssh_private_key or field:<name>", vault.ErrInvalid, field)
	}
	return nil
}

func findAttachment(it *vault.Item, ref string) (vault.Attachment, error) {
	var match []vault.Attachment
	for _, a := range it.Attachments {
		if a.ID == ref {
			return a, nil
		}
		if a.FileName == ref {
			match = append(match, a)
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return vault.Attachment{}, fmt.Errorf("%w: attachment %q on item %q", vault.ErrNotFound, ref, it.Name)
	default:
		return vault.Attachment{}, fmt.Errorf("%w: item %q has several attachments named %q; pass the id", vault.ErrAmbiguous, it.Name, ref)
	}
}

// shellQuote quotes a file name for the example command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
