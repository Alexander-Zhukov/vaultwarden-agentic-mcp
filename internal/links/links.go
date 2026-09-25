// Package links keeps one-time links: short-lived capability URLs through
// which a value leaves the vault into a process, or enters it from a human,
// without passing through the model's context.
//
// A link is a random token in memory only. It works once, expires on its own,
// and dies with the process; nothing about it is ever logged.
package links

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Kind is what a link does.
type Kind string

// Link kinds.
const (
	// KindValue downloads one value of an item.
	KindValue Kind = "value"
	// KindAttachment downloads one attachment.
	KindAttachment Kind = "attachment"
	// KindUpload accepts one value or file into an item.
	KindUpload Kind = "upload"
)

// ErrFull is returned when too many links are outstanding.
var ErrFull = errors.New("too many outstanding links")

// Link is one outstanding capability.
type Link struct {
	Kind   Kind
	ItemID string
	// Field names the value to download or replace, as vault.Item.Values
	// spells it; empty for attachments.
	Field string
	// Attachment is the attachment id to download, or the file name an
	// upload stores.
	Attachment string
	// Client is who issued the link, for the audit log.
	Client string
	// Collections is the issuing client's narrowing, checked again when the
	// link is redeemed: the item may have moved out of reach since.
	Collections []string
	Expires     time.Time
}

// Store holds outstanding links.
type Store struct {
	mu    sync.Mutex
	now   func() time.Time
	links map[string]Link
	// max bounds the table: an agent issuing links in a loop fills it long
	// before it fills memory.
	max int
}

// NewStore returns an empty store.
func NewStore(now func() time.Time, maxOutstanding int) *Store {
	return &Store{now: now, links: map[string]Link{}, max: maxOutstanding}
}

// Issue records a link and returns its token.
func (s *Store) Issue(l Link) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.links) >= s.max {
		return "", ErrFull
	}
	s.links[token] = l
	return token, nil
}

// Take removes and returns a live link of one of the given kinds. A link is
// consumed before it is served, so two concurrent requests with one token
// cannot both succeed. A request of the wrong kind leaves the link alone: a
// stray GET must not spend an upload link.
func (s *Store) Take(token string, kinds ...Kind) (Link, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[token]
	if !ok || !slices.Contains(kinds, l.Kind) {
		return Link{}, false
	}
	delete(s.links, token)
	if !s.now().Before(l.Expires) {
		return Link{}, false
	}
	return l, true
}

// Peek returns a live link of the given kind without consuming it — for the
// upload form, which is shown before the value is sent.
func (s *Store) Peek(token string, kind Kind) (Link, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[token]
	if !ok || l.Kind != kind || !s.now().Before(l.Expires) {
		return Link{}, false
	}
	return l, true
}

// Revoke drops every link of an item, after the item changed hands or was
// deleted.
func (s *Store) Revoke(itemID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, l := range s.links {
		if l.ItemID == itemID {
			delete(s.links, token)
		}
	}
}

// Outstanding counts live links.
func (s *Store) Outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return len(s.links)
}

func (s *Store) sweepLocked() {
	now := s.now()
	for token, l := range s.links {
		if !now.Before(l.Expires) {
			delete(s.links, token)
		}
	}
}
