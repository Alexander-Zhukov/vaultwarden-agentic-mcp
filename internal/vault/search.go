package vault

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// fingerprintInfo separates the fingerprint key from every other use of the
// user key.
const fingerprintInfo = "vaultwarden-mcp value fingerprint"

// Fingerprint returns a short keyed digest of a value. Equal values give equal
// fingerprints within one account, so copies of a secret are visible without
// the secret; the key never leaves the process, so a fingerprint cannot be
// brute-forced back into a weak password by anyone who only sees it.
func (s *Snapshot) Fingerprint(value string) string {
	if value == "" {
		return ""
	}
	key, err := hkdf.Expand(sha256.New, s.userKey.Bytes(), fingerprintInfo, 32)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// Value is one value of an item with where it lives.
type Value struct {
	// Field names the value: password, totp, notes, ssh_private_key,
	// field:<name>, card:<name> or identity:<name>.
	Field  string
	Value  string
	Secret bool
}

// Values lists every non-empty value of an item. A secure note's text is its
// secret; on other items notes are description.
func (it *Item) Values() []Value {
	var out []Value
	add := func(field, value string, secret bool) {
		if value != "" {
			out = append(out, Value{Field: field, Value: value, Secret: secret})
		}
	}
	add("username", it.Username, false)
	add("password", it.Password, true)
	add("totp", it.TOTP, true)
	add("notes", it.Notes, it.Type == TypeNote)
	if it.SSH != nil {
		add("ssh_private_key", it.SSH.Private, true)
		add("ssh_public_key", it.SSH.Public, false)
	}
	for _, f := range it.Fields {
		add("field:"+f.Name, f.Value, f.Kind == FieldHidden)
	}
	for name, v := range it.Card {
		add("card:"+name, v, IsSecretCardField(name))
	}
	for name, v := range it.Identity {
		add("identity:"+name, v, IsSecretIdentityField(name))
	}
	return out
}

// Secret returns one secret value of the item by its field name, as Values
// spells it.
func (it *Item) Secret(field string) (Value, bool) {
	for _, v := range it.Values() {
		if v.Field == field {
			return v, true
		}
	}
	return Value{}, false
}

// Filter narrows a listing.
type Filter struct {
	Collection string
	Type       ItemType
	Trash      bool
}

// ItemsMatching lists items matching a filter.
func (s *Snapshot) ItemsMatching(f Filter) ([]*Item, error) {
	var within string
	if f.Collection != "" {
		c, err := s.Collection(f.Collection)
		if err != nil {
			return nil, err
		}
		within = c.ID
	}
	var out []*Item
	for i := range s.Items {
		it := &s.Items[i]
		if (it.Deleted != nil) != f.Trash {
			continue
		}
		if within != "" && !slices.Contains(it.CollectionIDs, within) {
			continue
		}
		if f.Type != "" && it.Type != f.Type {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// Match is a search hit: the item and the places the query was found.
type Match struct {
	Item    *Item
	Matched []string
	score   int
}

// Search finds items whose description matches every word of the query: name,
// username, addresses, notes, custom field names and non-secret field values.
// Secret values are never searched here; FindValue is for that.
func (s *Snapshot) Search(query string, f Filter) ([]Match, error) {
	words := strings.Fields(strings.ToLower(query))
	items, err := s.ItemsMatching(f)
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, it := range items {
		m := Match{Item: it}
		ok := true
		for _, w := range words {
			hit, score := matchWord(it, w)
			if hit == "" {
				ok = false
				break
			}
			if !slices.Contains(m.Matched, hit) {
				m.Matched = append(m.Matched, hit)
			}
			m.score += score
		}
		if ok {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].Item.Name < out[j].Item.Name
	})
	return out, nil
}

// matchWord returns the best place one word matches and its weight: the name
// counts most, and an exact or prefix hit on the name more than a substring.
func matchWord(it *Item, w string) (string, int) {
	name := strings.ToLower(it.Name)
	switch {
	case name == w:
		return "name", 100
	case strings.HasPrefix(name, w):
		return "name", 80
	case strings.Contains(name, w):
		return "name", 60
	}
	if strings.Contains(strings.ToLower(it.Username), w) {
		return "username", 40
	}
	for _, u := range it.URIs {
		if strings.Contains(strings.ToLower(u.URI), w) {
			return "uri", 40
		}
	}
	for _, f := range it.Fields {
		if strings.Contains(strings.ToLower(f.Name), w) {
			return "field:" + f.Name, 30
		}
		if f.Kind != FieldHidden && strings.Contains(strings.ToLower(f.Value), w) {
			return "field:" + f.Name, 20
		}
	}
	if it.Type != TypeNote && strings.Contains(strings.ToLower(it.Notes), w) {
		return "notes", 20
	}
	for _, a := range it.Attachments {
		if strings.Contains(strings.ToLower(a.FileName), w) {
			return "attachment", 20
		}
	}
	return "", 0
}

// ValueMatch is an item holding a given value.
type ValueMatch struct {
	Item   *Item
	Fields []string
}

// MinFindLength is the shortest value FindValue compares. Anything shorter —
// a PIN, a card code — would turn the search into a guessing oracle.
const MinFindLength = 8

// FindValue lists the items holding exactly this value, in any field. Values
// shorter than MinFindLength are neither searched for nor compared against,
// and secrets the account may not view are skipped. The comparison is
// constant-time per value.
func (s *Snapshot) FindValue(value string, f Filter) ([]ValueMatch, error) {
	if len(value) < MinFindLength {
		return nil, fmt.Errorf("%w: a value shorter than %d characters cannot be searched for", ErrInvalid, MinFindLength)
	}
	items, err := s.ItemsMatching(f)
	if err != nil {
		return nil, err
	}
	var out []ValueMatch
	for _, it := range items {
		var fields []string
		for _, v := range it.Values() {
			if v.Secret && !it.Viewable {
				continue
			}
			if len(v.Value) >= MinFindLength && hmac.Equal([]byte(v.Value), []byte(value)) {
				fields = append(fields, v.Field)
			}
		}
		if len(fields) > 0 {
			out = append(out, ValueMatch{Item: it, Fields: fields})
		}
	}
	return out, nil
}

// Copies lists the other items holding any secret value of the given item.
// Secrets the account may not view take part on neither side.
func (s *Snapshot) Copies(it *Item) []ValueMatch {
	if !it.Viewable {
		return nil
	}
	secrets := map[string][]string{}
	for _, v := range it.Values() {
		if v.Secret {
			secrets[v.Value] = append(secrets[v.Value], v.Field)
		}
	}
	var out []ValueMatch
	for i := range s.Items {
		other := &s.Items[i]
		if other.ID == it.ID || other.Deleted != nil || !other.Viewable {
			continue
		}
		var fields []string
		for _, v := range other.Values() {
			if _, ok := secrets[v.Value]; ok && v.Secret {
				fields = append(fields, v.Field)
			}
		}
		if len(fields) > 0 {
			out = append(out, ValueMatch{Item: other, Fields: fields})
		}
	}
	return out
}
