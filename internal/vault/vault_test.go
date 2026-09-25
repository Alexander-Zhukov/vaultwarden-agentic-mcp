package vault

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

func testKey(t *testing.T) keys.SymmetricKey {
	t.Helper()
	k, err := keys.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	return &Snapshot{
		userKey: testKey(t),
		Collections: []Collection{
			{ID: "c1", Name: "infra"}, {ID: "c2", Name: "agents"}, {ID: "c3", Name: "Infra"}, {ID: "c4", Name: "ro", ReadOnly: true},
		},
		Items: []Item{
			{ID: "i1", Name: "API_TOKEN", CollectionIDs: []string{"c1"}, Type: TypeLogin, Password: "same-secret", Username: "bot", Viewable: true},
			{ID: "i2", Name: "API_TOKEN", CollectionIDs: []string{"c2"}, Type: TypeLogin, Password: "same-secret", Viewable: true},
			{ID: "i3", Name: "deploy key", CollectionIDs: []string{"c1"}, Type: TypeSSHKey, SSH: &SSHKey{Private: "priv", Public: "ssh-ed25519 AAA"}},
			{ID: "i4", Name: "note", CollectionIDs: []string{"c2"}, Type: TypeNote, Notes: "the secret text"},
			{ID: "i5", Name: "gone", CollectionIDs: []string{"c1"}, Type: TypeLogin, Password: "x", Deleted: &time.Time{}},
			{
				ID: "i6", Name: "hidden", CollectionIDs: []string{"c1"}, Type: TypeLogin,
				Fields: []Field{{Name: "client_secret", Value: "hv", Kind: FieldHidden}, {Name: "region", Value: "eu-west", Kind: FieldText}},
			},
		},
	}
}

func TestCollectionResolution(t *testing.T) {
	t.Parallel()
	snap := testSnapshot(t)
	tests := []struct {
		ref  string
		want string
		err  error
	}{
		{"c2", "c2", nil},
		{"agents", "c2", nil},
		{"AGENTS", "c2", nil},
		{"infra", "c1", nil},
		{"INFRA", "", ErrAmbiguous},
		{"missing", "", ErrNotFound},
		{" ", "", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			t.Parallel()
			got, err := snap.Collection(tt.ref)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err %v, want %v", err, tt.err)
			}
			if err == nil && got.ID != tt.want {
				t.Fatalf("got %s, want %s", got.ID, tt.want)
			}
		})
	}
}

func TestItemResolution(t *testing.T) {
	t.Parallel()
	snap := testSnapshot(t)
	tests := []struct {
		name string
		ref  ItemRef
		want string
		err  error
	}{
		{"by id", ItemRef{Ref: "i2"}, "i2", nil},
		{"shared name is ambiguous", ItemRef{Ref: "API_TOKEN"}, "", ErrAmbiguous},
		{"collection disambiguates", ItemRef{Ref: "API_TOKEN", Collection: "agents"}, "i2", nil},
		{"case-insensitive fallback", ItemRef{Ref: "DEPLOY KEY"}, "i3", nil},
		{"trash is hidden", ItemRef{Ref: "gone"}, "", ErrNotFound},
		{"trash on request", ItemRef{Ref: "gone", Trash: true}, "i5", nil},
		{"trashed id still resolves", ItemRef{Ref: "i5"}, "i5", nil},
		{"collection filter excludes", ItemRef{Ref: "note", Collection: "infra"}, "", ErrNotFound},
		{"unknown collection", ItemRef{Ref: "note", Collection: "nope"}, "", ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := snap.Item(tt.ref)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err %v, want %v", err, tt.err)
			}
			if err == nil && got.ID != tt.want {
				t.Fatalf("got %s, want %s", got.ID, tt.want)
			}
		})
	}
}

func TestValuesClassifySecrets(t *testing.T) {
	t.Parallel()
	snap := testSnapshot(t)
	got := map[string]bool{}
	for _, it := range []string{"i3", "i4", "i6"} {
		item, err := snap.Item(ItemRef{Ref: it})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range item.Values() {
			got[item.ID+"/"+v.Field] = v.Secret
		}
	}
	want := map[string]bool{
		"i3/ssh_private_key": true, "i3/ssh_public_key": false,
		"i4/notes":               true,
		"i6/field:client_secret": true, "i6/field:region": false,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("secret classification (-want +got):\n%s", diff)
	}
}

func TestSearchNeverMatchesSecrets(t *testing.T) {
	t.Parallel()
	snap := testSnapshot(t)
	tests := []struct {
		query string
		want  []string
	}{
		{"api", []string{"i1", "i2"}},
		{"bot", []string{"i1"}},
		{"eu-west", []string{"i6"}},
		{"client_secret", []string{"i6"}},
		{"hv", nil},
		{"same-secret", nil},
		{"secret text", nil},
		{"deploy key", []string{"i3"}},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			t.Parallel()
			matches, err := snap.Search(tt.query, Filter{})
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, m := range matches {
				ids = append(ids, m.Item.ID)
			}
			if diff := cmp.Diff(tt.want, ids); diff != "" {
				t.Fatalf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindValueAndCopies(t *testing.T) {
	t.Parallel()
	snap := testSnapshot(t)
	found, err := snap.FindValue("same-secret", Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d", len(found))
	}
	if _, err := snap.FindValue("1234", Filter{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a short value must not be searchable: %v", err)
	}
	snap.Items[1].Viewable = false
	if found, _ := snap.FindValue("same-secret", Filter{}); len(found) != 1 {
		t.Fatalf("a secret hidden from the account must not match: %d", len(found))
	}
	snap.Items[1].Viewable = true
	it, err := snap.Item(ItemRef{Ref: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	copies := snap.Copies(it)
	if len(copies) != 1 || copies[0].Item.ID != "i2" || copies[0].Fields[0] != "password" {
		t.Fatalf("copies %+v", copies)
	}
	if a, b := snap.Fingerprint("same"), snap.Fingerprint("same"); a != b || a == "" || a == snap.Fingerprint("other") {
		t.Fatal("fingerprints must be stable and distinguish values")
	}
	other := testSnapshot(t)
	if snap.Fingerprint("same") == other.Fingerprint("same") {
		t.Fatal("fingerprints must be keyed per account")
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	snap := testSnapshot(t)
	snap.Items = append(snap.Items,
		Item{
			ID: "e1", Name: "soon", Type: TypeLogin, Password: "p1", Notes: "Description: x\nUsed by: y",
			Fields: []Field{{Name: "expires", Value: "2026-10-01", Kind: FieldText}},
		},
		Item{ID: "e2", Name: "past", Type: TypeLogin, Password: "p2", Fields: []Field{{Name: "expires", Value: "2026-01-01", Kind: FieldText}}},
		Item{ID: "e3", Name: "bad", Type: TypeLogin, Password: "p3", Fields: []Field{{Name: "expires", Value: "next year", Kind: FieldText}}},
		Item{
			ID: "e5", Name: "hidden expiry", Type: TypeLogin, Password: "p5", Notes: "Description: x\nUsed by: y",
			Fields: []Field{{Name: "expires", Value: "SECRET-NOT-A-DATE", Kind: FieldHidden}},
		},
		Item{ID: "e4", Name: "empty", Type: TypeLogin},
	)
	var items []*Item
	for i := range snap.Items {
		if snap.Items[i].Deleted == nil {
			items = append(items, &snap.Items[i])
		}
	}
	rules := CheckRules{NotesPrefixes: []string{"Description:", "Used by:"}, ExpiryField: "expires", ExpiryHorizon: 14 * 24 * time.Hour}
	got := map[string][]IssueKind{}
	for _, i := range snap.Check(items, rules, now) {
		got[i.ItemID] = append(got[i.ItemID], i.Kind)
	}
	want := map[string][]IssueKind{
		"i1": {IssueDuplicate, IssueNotesFormat}, "i2": {IssueDuplicate, IssueNotesFormat},
		"i3": {IssueNotesFormat}, "i6": {IssueNotesFormat},
		"e1": {IssueExpiresSoon},
		"e2": {IssueExpired, IssueNotesFormat}, "e3": {IssueBadExpiry, IssueNotesFormat},
		"e4": {IssueEmptySecret, IssueNotesFormat},
	}
	for _, i := range snap.Check(items, rules, now) {
		if strings.Contains(i.Detail, "SECRET-NOT-A-DATE") {
			t.Fatalf("a hidden field's value was quoted: %+v", i)
		}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("(-want +got):\n%s", diff)
	}
}

func TestItemRoundTrip(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	match := 3
	it := Item{
		OrganizationID: "org", Type: TypeLogin, Name: "n", Notes: "notes", Username: "u", Password: "p", TOTP: "t",
		URIs:            []URI{{URI: "https://x.test", Match: &match}},
		Fields:          []Field{{Name: "f", Value: "v", Kind: FieldHidden}},
		PasswordHistory: []PasswordChange{{Password: "old", Changed: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}},
		key:             key,
	}
	c, err := encryptItem(&it)
	if err != nil {
		t.Fatal(err)
	}
	if c.Login.URIs[0].URIChecksum == nil {
		t.Fatal("uri checksum must be written")
	}
	c.ViewPassword = true
	got, err := decryptCipher(c, key)
	if err != nil {
		t.Fatal(err)
	}
	opts := cmp.Options{cmp.AllowUnexported(Item{}), cmp.Comparer(func(a, b keys.SymmetricKey) bool { return string(a.Bytes()) == string(b.Bytes()) })}
	it.Viewable = true
	if diff := cmp.Diff(it, got, opts); diff != "" {
		t.Fatalf("(-want +got):\n%s", diff)
	}
	if _, err := decryptCipher(c, testKey(t)); err == nil {
		t.Fatal("a foreign key must not decrypt")
	}
}

func TestItemWithPerItemKey(t *testing.T) {
	t.Parallel()
	owner, itemKey := testKey(t), testKey(t)
	wrapped, err := owner.EncryptKey(itemKey)
	if err != nil {
		t.Fatal(err)
	}
	it := Item{Type: TypeNote, Name: "n", Notes: "secret", key: itemKey, wrappedKey: &wrapped}
	c, err := encryptItem(&it)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptCipher(c, owner)
	if err != nil || got.Notes != "secret" {
		t.Fatalf("got %q, %v", got.Notes, err)
	}
}

func TestSaltFromToken(t *testing.T) {
	t.Parallel()
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"bot@example.test"}`))
	tests := []struct {
		name string
		resp bitwarden.TokenResponse
		want string
	}{
		{"jwt claim", bitwarden.TokenResponse{AccessToken: "h." + payload + ".s"}, "bot@example.test"},
		{"not a jwt", bitwarden.TokenResponse{AccessToken: "opaque"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := salt(&tt.resp); got != tt.want {
				t.Fatalf("got %q", got)
			}
		})
	}
}

func TestDeviceIsStable(t *testing.T) {
	t.Parallel()
	a, b := deviceFor("user.1", "x"), deviceFor("user.1", "x")
	if a != b || a.Identifier == deviceFor("user.2", "x").Identifier || len(a.Identifier) != 36 {
		t.Fatalf("device %+v", a)
	}
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute}
	for i, w := range want {
		if got := backoff(i+1, 15*time.Second, 2*time.Minute); got != w {
			t.Fatalf("failure %d: %s, want %s", i+1, got, w)
		}
	}
}

func TestResolveWritable(t *testing.T) {
	t.Parallel()
	snap := testSnapshot(t)
	snap.Collections = append(snap.Collections, Collection{ID: "x", Name: "other", OrganizationID: "org2"})
	if _, err := resolveWritable(snap, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("no collection must be refused")
	}
	if _, err := resolveWritable(snap, []string{"ro"}); !errors.Is(err, ErrReadOnly) {
		t.Fatal("read-only collection must be refused")
	}
	if _, err := resolveWritable(snap, []string{"infra", "other"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("collections of two organizations must be refused")
	}
	cols, err := resolveWritable(snap, []string{"infra", "c1"})
	if err != nil || len(cols) != 1 {
		t.Fatalf("duplicates must collapse: %v %v", cols, err)
	}
}

func TestRecordHistory(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	current := &Item{Password: "old", Fields: []Field{
		{Name: "api", Value: "h1", Kind: FieldHidden}, {Name: "gone", Value: "h2", Kind: FieldHidden}, {Name: "t", Value: "x", Kind: FieldText},
	}}
	next := cloneItem(current)
	next.Password = "new"
	next.Fields = []Field{{Name: "api", Value: "h1-rotated", Kind: FieldHidden}, {Name: "t", Value: "y", Kind: FieldText}}
	recordHistory(current, &next, now)
	var got []string
	for _, h := range next.PasswordHistory {
		got = append(got, h.Password)
	}
	if diff := cmp.Diff([]string{"old", "api: h1", "gone: h2"}, got); diff != "" {
		t.Fatalf("(-want +got):\n%s", diff)
	}
	if next.passwordRevised == nil {
		t.Fatal("password revision date not set")
	}
}

func TestURIChecksumMismatchDropsURI(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	it := Item{Type: TypeLogin, Name: "n", URIs: []URI{{URI: "https://good.test"}, {URI: "https://other.test"}}, key: key}
	c, err := encryptItem(&it)
	if err != nil {
		t.Fatal(err)
	}
	// Swap the second URI's ciphertext for the first one's, as a server
	// shuffling data between entries would: its checksum no longer matches.
	c.Login.URIs[1].URI = c.Login.URIs[0].URI
	c.Login.URIs[0].URIChecksum = nil
	got, err := decryptCipher(c, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.URIs) != 1 || got.URIs[0].URI != "https://good.test" {
		t.Fatalf("uris %+v", got.URIs)
	}
}

func FuzzExpiry(f *testing.F) {
	for _, seed := range []string{"2026-09-25", "2026-09-25T10:00:00Z", "soon", "", "0000-00-00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		it := &Item{Fields: []Field{{Name: "expires", Value: raw, Kind: FieldText}}}
		at, ok, err := it.Expiry("expires", time.UTC)
		if err == nil && ok && at.IsZero() {
			t.Fatalf("%q parsed to the zero time", raw)
		}
	})
}

func FuzzSalt(f *testing.F) {
	f.Add("a.eyJlbWFpbCI6ImFAYi5jIn0.c")
	f.Add("...")
	f.Add("opaque")
	f.Fuzz(func(t *testing.T, token string) {
		_ = salt(&bitwarden.TokenResponse{AccessToken: token})
	})
}
