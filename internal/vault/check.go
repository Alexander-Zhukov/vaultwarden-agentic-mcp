package vault

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CheckRules configures the checks of Check. The notes convention is a policy
// of the deployment, not of this service, so it is empty unless configured.
type CheckRules struct {
	// NotesPrefixes lists the prefixes every item's notes must have a line
	// for, e.g. "Description:", "Used by:", "Rotation:".
	NotesPrefixes []string
	// ExpiryField is the custom field holding an expiry date.
	ExpiryField string
	// ExpiryHorizon flags items expiring within this window.
	ExpiryHorizon time.Duration
	// Zone is where a bare date ends; dates in findings are shown in it.
	Zone *time.Location
}

// IssueKind classifies a finding.
type IssueKind string

// Findings of Check.
const (
	IssueNotesFormat   IssueKind = "notes_format"
	IssueExpired       IssueKind = "expired"
	IssueExpiresSoon   IssueKind = "expires_soon"
	IssueBadExpiry     IssueKind = "bad_expiry"
	IssueEmptySecret   IssueKind = "empty_secret"
	IssueDuplicate     IssueKind = "duplicate"
	IssueUndecryptable IssueKind = "undecryptable"
)

// Issue is one finding about one item.
type Issue struct {
	ItemID   string
	ItemName string
	Kind     IssueKind
	Detail   string
}

// Expiry reads an item's expiry date from its custom field. A date without a
// time means the end of that day in the given zone.
func (it *Item) Expiry(field string, zone *time.Location) (time.Time, bool, error) {
	f, ok := it.Field(field)
	// Only a text field is metadata; a hidden field of that name is a secret
	// and is never read, parsed or quoted here.
	if !ok || f.Kind != FieldText || strings.TrimSpace(f.Value) == "" {
		return time.Time{}, false, nil
	}
	raw := strings.TrimSpace(f.Value)
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true, nil
	}
	day, err := time.ParseInLocation(time.DateOnly, raw, zone)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("field %q: %q is neither YYYY-MM-DD nor RFC 3339", field, raw)
	}
	// The last second of that calendar day, which is not always 24 hours
	// after its start.
	return day.AddDate(0, 0, 1).Add(-time.Second), true, nil
}

// Check inspects items for the problems an operator would want to know about
// before they bite: a convention not followed, a credential about to expire,
// an item without a value, a secret stored twice.
func (s *Snapshot) Check(items []*Item, rules CheckRules, now time.Time) []Issue {
	var out []Issue
	for _, it := range items {
		out = append(out, checkNotes(it, rules.NotesPrefixes)...)
		if rules.ExpiryField != "" {
			out = append(out, checkExpiry(it, rules, now)...)
		}
		if !hasSecret(it) {
			out = append(out, Issue{it.ID, it.Name, IssueEmptySecret, "the item holds no secret value"})
		}
		// Copies are looked for across everything visible: the copy that
		// gets forgotten at rotation is usually in another collection.
		if copies := s.Copies(it); len(copies) > 0 {
			names := make([]string, len(copies))
			for i, c := range copies {
				names[i] = fmt.Sprintf("%s (%s)", c.Item.Name, strings.Join(s.CollectionNames(c.Item.CollectionIDs), ", "))
			}
			sort.Strings(names)
			out = append(out, Issue{it.ID, it.Name, IssueDuplicate, "same secret value as: " + strings.Join(names, "; ")})
		}
	}
	for _, b := range s.Broken {
		out = append(out, Issue{b.ID, "", IssueUndecryptable, b.Error})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ItemName != out[j].ItemName {
			return out[i].ItemName < out[j].ItemName
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func checkNotes(it *Item, prefixes []string) []Issue {
	if len(prefixes) == 0 || it.Type == TypeNote {
		return nil
	}
	lines := strings.Split(it.Notes, "\n")
	var missing []string
	for _, p := range prefixes {
		found := false
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), p) && strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), p)) != "" {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []Issue{{it.ID, it.Name, IssueNotesFormat, "notes lack a filled line for: " + strings.Join(missing, ", ")}}
}

func checkExpiry(it *Item, rules CheckRules, now time.Time) []Issue {
	zone := rules.Zone
	if zone == nil {
		zone = time.UTC
	}
	at, ok, err := it.Expiry(rules.ExpiryField, zone)
	switch {
	case err != nil:
		return []Issue{{it.ID, it.Name, IssueBadExpiry, err.Error()}}
	case !ok:
		return nil
	case !at.After(now):
		return []Issue{{it.ID, it.Name, IssueExpired, "expired " + at.In(zone).Format(time.DateOnly)}}
	case at.Sub(now) <= rules.ExpiryHorizon:
		return []Issue{{it.ID, it.Name, IssueExpiresSoon, "expires " + at.In(zone).Format(time.DateOnly)}}
	default:
		return nil
	}
}

func hasSecret(it *Item) bool {
	for _, v := range it.Values() {
		if v.Secret {
			return true
		}
	}
	return len(it.Attachments) > 0
}
