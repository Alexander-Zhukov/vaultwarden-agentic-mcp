package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// sendSeedSize is the length of the key material a Send link carries.
const sendSeedSize = 16

// SendInfo describes a share link without its content.
type SendInfo struct {
	ID          string
	AccessID    string
	Name        string
	Expires     *time.Time
	Deletes     time.Time
	AccessCount int
	MaxAccess   *int
	Disabled    bool
}

func decryptSendInfo(s bitwarden.Send, userKey keys.SymmetricKey) SendInfo {
	info := SendInfo{ID: s.ID, AccessID: s.AccessID, AccessCount: s.AccessCount, MaxAccess: s.MaxAccessCount, Disabled: s.Disabled}
	info.Deletes, _ = parseTime(s.DeletionDate) // informational
	if s.ExpirationDate != nil {
		if t, err := parseTime(*s.ExpirationDate); err == nil {
			info.Expires = &t
		}
	}
	info.Name = "[undecryptable]"
	if enc, err := keys.ParseEncString(s.Key); err == nil {
		if seed, err := userKey.Decrypt(enc); err == nil {
			if k, err := keys.SendKey(seed); err == nil {
				if name, err := k.DecryptString(s.Name); err == nil {
					info.Name = name
				}
			}
		}
	}
	return info
}

// NewSend describes a text share link.
type NewSend struct {
	Name      string
	Text      string
	Notes     string
	Expires   time.Time
	MaxAccess *int
}

// CreateSend stores a text Send and returns its link. The link's fragment holds
// the key; the server stores only what it cannot read.
func (v *Vault) CreateSend(ctx context.Context, n NewSend, webURL string) (SendInfo, string, error) {
	if n.Text == "" {
		return SendInfo{}, "", fmt.Errorf("%w: nothing to share", ErrInvalid)
	}
	snap, err := v.Snapshot(ctx)
	if err != nil {
		return SendInfo{}, "", err
	}
	seed := make([]byte, sendSeedSize)
	if _, err := rand.Read(seed); err != nil {
		return SendInfo{}, "", fmt.Errorf("read random seed: %w", err)
	}
	sendKey, err := keys.SendKey(seed)
	if err != nil {
		return SendInfo{}, "", err
	}
	e := &encoder{key: sendKey}
	name := e.str(n.Name)
	text := e.str(n.Text)
	notes := e.opt(n.Notes)
	if e.err != nil {
		return SendInfo{}, "", e.err
	}
	wrapped, err := snap.userKey.Encrypt(seed)
	if err != nil {
		return SendInfo{}, "", err
	}
	expires := bitwarden.FormatTime(n.Expires)
	req := bitwarden.Send{
		Type:           0,
		Name:           name,
		Notes:          notes,
		Key:            wrapped.String(),
		Text:           &bitwarden.SendText{Text: text, Hidden: true},
		MaxAccessCount: n.MaxAccess,
		ExpirationDate: &expires,
		// The server deletes the Send at this moment; expiring and deleting
		// together leaves nothing behind.
		DeletionDate: expires,
		HideEmail:    true,
	}
	var resp *bitwarden.Send
	err = v.retry(func() error {
		var err error
		resp, err = v.client.CreateSend(ctx, req)
		return err
	})
	if err != nil {
		return SendInfo{}, "", fmt.Errorf("create send: %w", err)
	}
	info := decryptSendInfo(*resp, snap.userKey)
	link := strings.TrimRight(webURL, "/") + "/#/send/" + resp.AccessID + "/" + base64.RawURLEncoding.EncodeToString(seed)
	return info, link, nil
}

// DeleteSend removes a share link, which stops it working at once.
func (v *Vault) DeleteSend(ctx context.Context, id string) error {
	return v.retry(func() error { return v.client.DeleteSend(ctx, id) })
}
