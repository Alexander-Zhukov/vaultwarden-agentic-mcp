package vault

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// ErrTooLarge refuses an attachment over the configured limit rather than
// truncating it.
var ErrTooLarge = errors.New("attachment exceeds the size limit")

// findAttachment resolves an attachment by id or file name.
func findAttachment(it *Item, ref string) (Attachment, error) {
	var byName []Attachment
	for _, a := range it.Attachments {
		if a.ID == ref {
			return a, nil
		}
		if a.FileName == ref {
			byName = append(byName, a)
		}
	}
	switch len(byName) {
	case 0:
		return Attachment{}, fmt.Errorf("%w: attachment %q on item %q", ErrNotFound, ref, it.Name)
	case 1:
		return byName[0], nil
	default:
		return Attachment{}, fmt.Errorf("%w: item %q has %d attachments named %q; pass the id", ErrAmbiguous, it.Name, len(byName), ref)
	}
}

// AddAttachment encrypts a file with a fresh key and stores it with the item.
func (v *Vault) AddAttachment(ctx context.Context, ref ItemRef, fileName string, content []byte) (Attachment, error) {
	fileName = filepath.Base(strings.TrimSpace(fileName))
	if fileName == "" || fileName == "." || fileName == string(filepath.Separator) {
		return Attachment{}, fmt.Errorf("%w: file name is required", ErrInvalid)
	}
	if int64(len(content)) > v.maxFile {
		return Attachment{}, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(content), v.maxFile)
	}
	var added Attachment
	err := v.mutate(ctx, func(snap *Snapshot) error {
		it, err := snap.Item(ref)
		if err != nil {
			return err
		}
		if err := checkEditable(snap, it); err != nil {
			return err
		}
		fileKey, err := keys.GenerateSymmetricKey()
		if err != nil {
			return err
		}
		wrapped, err := it.key.EncryptKey(fileKey)
		if err != nil {
			return err
		}
		encName, err := it.key.EncryptString(fileName)
		if err != nil {
			return err
		}
		data, err := fileKey.EncryptBuffer(content)
		if err != nil {
			return err
		}
		var slot bitwarden.AttachmentSlot
		err = v.retry(func() error {
			var err error
			slot, err = v.client.CreateAttachment(ctx, it.ID, bitwarden.NewAttachment{
				Key: wrapped, FileName: encName, FileSize: int64(len(data)),
			})
			return err
		})
		if err != nil {
			return fmt.Errorf("register attachment: %w", err)
		}
		err = v.retry(func() error { return v.client.UploadAttachment(ctx, slot, encName, data) })
		if err != nil {
			// The item already lists the slot; left behind, it would show as
			// a file nobody can download.
			cleanup := v.retry(func() error { return v.client.DeleteAttachment(ctx, it.ID, slot.ID) })
			return errors.Join(fmt.Errorf("upload attachment: %w", err), cleanup)
		}
		added = Attachment{ID: slot.ID, FileName: fileName, Size: int64(len(content)), key: fileKey}
		return nil
	})
	return added, err
}

// AttachmentContent downloads and decrypts an attachment.
func (v *Vault) AttachmentContent(ctx context.Context, ref ItemRef, attachment string) (Attachment, []byte, error) {
	snap, err := v.Snapshot(ctx)
	if err != nil {
		return Attachment{}, nil, err
	}
	it, err := snap.Item(ref)
	if err != nil {
		return Attachment{}, nil, err
	}
	att, err := findAttachment(it, attachment)
	if err != nil {
		return Attachment{}, nil, err
	}
	// The encrypted form is larger than the plaintext by a header and padding.
	limit := v.maxFile + 1 + 16 + 32 + 16
	var data []byte
	err = v.retry(func() error {
		var err error
		data, err = v.client.AttachmentContent(ctx, it.ID, att.ID, limit)
		return err
	})
	if errors.Is(err, bitwarden.ErrTooLarge) {
		return Attachment{}, nil, fmt.Errorf("%w: %s", ErrTooLarge, att.FileName)
	}
	if err != nil {
		return Attachment{}, nil, fmt.Errorf("download attachment: %w", err)
	}
	plain, err := att.key.DecryptBuffer(data)
	if err != nil {
		return Attachment{}, nil, fmt.Errorf("decrypt attachment: %w", err)
	}
	return att, plain, nil
}

// DeleteAttachment removes an attachment from its item.
func (v *Vault) DeleteAttachment(ctx context.Context, ref ItemRef, attachment string) (Attachment, error) {
	var removed Attachment
	err := v.mutate(ctx, func(snap *Snapshot) error {
		it, err := snap.Item(ref)
		if err != nil {
			return err
		}
		if err := checkEditable(snap, it); err != nil {
			return err
		}
		removed, err = findAttachment(it, attachment)
		if err != nil {
			return err
		}
		return v.retry(func() error { return v.client.DeleteAttachment(ctx, it.ID, removed.ID) })
	})
	return removed, err
}
