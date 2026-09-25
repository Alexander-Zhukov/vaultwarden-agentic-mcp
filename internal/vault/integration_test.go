//go:build integration

package vault_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwtest"
)

func open(t *testing.T, acct *vwtest.Account) *vault.Vault {
	t.Helper()
	v, err := vault.New(vault.Config{
		Server: bitwarden.Config{
			BaseURL: vwtest.ServerURL(t), Timeout: 30 * time.Second, MaxResponseBytes: 32 << 20,
		},
		Credentials:        vault.Credentials{ClientID: acct.ClientID, ClientSecret: config.Secret(acct.ClientSecret), Password: config.Secret(acct.Password)},
		DeviceName:         "vault-test",
		SyncTTL:            time.Minute,
		MaxAttachmentBytes: 1 << 20,
		Clock:              time.Now,
		TokenMargin:        5 * time.Minute,
		BackoffMin:         time.Second,
		BackoffMax:         time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestLiveVault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	owner := vwtest.NewAccount(ctx, t, "owner")
	org := owner.NewOrganization(ctx, t, "Machine", "infra")
	v := open(t, owner)

	admin, err := v.Admin(ctx, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CreateCollection(ctx, "agents", nil); err != nil {
		t.Fatal(err)
	}

	created, err := v.Create(ctx, vault.NewItem{
		Collections: []string{"infra"},
		Type:        vault.TypeLogin,
		Name:        "API_TOKEN",
		Notes:       "Description: token\nUsed by: ci\nRotation: yearly",
		Username:    "bot",
		Password:    "first",
		URIs:        []vault.URI{{URI: "https://example.test"}},
		Fields: []vault.Field{
			{Name: "expires", Value: time.Now().Add(72 * time.Hour).Format(time.DateOnly), Kind: vault.FieldText},
			{Name: "client_secret", Value: "hidden-value", Kind: vault.FieldHidden},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.OrganizationID != org.ID {
		t.Fatalf("created in %q, want organization %q", created.OrganizationID, org.ID)
	}

	updated, err := v.Update(ctx, vault.ItemRef{Ref: "API_TOKEN", Collection: "infra"}, func(it *vault.Item) error {
		it.Password = "second"
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(updated.PasswordHistory) != 1 || updated.PasswordHistory[0].Password != "first" {
		t.Fatalf("password history %+v", updated.PasswordHistory)
	}

	if _, err := v.Create(ctx, vault.NewItem{
		Collections: []string{"agents"}, Type: vault.TypeLogin, Name: "API_TOKEN", Password: "second",
	}); err != nil {
		t.Fatal(err)
	}
	snap, err := v.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snap.Item(vault.ItemRef{Ref: "API_TOKEN"}); !errors.Is(err, vault.ErrAmbiguous) {
		t.Fatalf("a name in two collections must be ambiguous, got %v", err)
	}
	it, err := snap.Item(vault.ItemRef{Ref: "API_TOKEN", Collection: "infra"})
	if err != nil {
		t.Fatal(err)
	}
	if copies := snap.Copies(it); len(copies) != 1 {
		t.Fatalf("copies %d, want 1", len(copies))
	}
	if found, _ := snap.FindValue("hidden-value", vault.Filter{}); len(found) != 1 || found[0].Fields[0] != "field:client_secret" {
		t.Fatalf("find value %+v", found)
	}
	issues := snap.Check([]*vault.Item{it}, vault.CheckRules{
		NotesPrefixes: []string{"Description:", "Used by:", "Rotation:"},
		ExpiryField:   "expires", ExpiryHorizon: 14 * 24 * time.Hour,
	}, time.Now())
	kinds := map[vault.IssueKind]bool{}
	for _, i := range issues {
		kinds[i.Kind] = true
	}
	if !kinds[vault.IssueExpiresSoon] || !kinds[vault.IssueDuplicate] || kinds[vault.IssueNotesFormat] {
		t.Fatalf("check findings %+v", issues)
	}

	att, err := v.AddAttachment(ctx, vault.ItemRef{Ref: it.ID}, "deploy.key", []byte("-----BEGIN KEY-----\nabc\n"))
	if err != nil {
		t.Fatalf("add attachment: %v", err)
	}
	_, content, err := v.AttachmentContent(ctx, vault.ItemRef{Ref: it.ID}, "deploy.key")
	if err != nil || string(content) != "-----BEGIN KEY-----\nabc\n" {
		t.Fatalf("attachment content %q, %v", content, err)
	}

	_, link, err := v.CreateSend(ctx, vault.NewSend{Name: "share", Text: "for-human", Expires: time.Now().Add(time.Hour)}, vwtest.ServerURL(t))
	if err != nil || !strings.Contains(link, "/#/send/") {
		t.Fatalf("send %q, %v", link, err)
	}

	// Everything written here reads back in the official client.
	out := owner.BW(ctx, t, `bw get item `+it.ID+` --session "$S" | node -e '
let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const i=JSON.parse(d);
console.log([i.login.password,i.passwordHistory[0].password,i.fields.map(f=>f.name+"="+f.value).join(","),i.attachments[0].fileName].join("|"))})'
bw get attachment deploy.key --itemid `+it.ID+` --output /tmp/a --session "$S" >&2
cat /tmp/a`)
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if lines[0] != "second|first|expires="+time.Now().Add(72*time.Hour).Format(time.DateOnly)+",client_secret=hidden-value|deploy.key" {
		t.Fatalf("bw sees %q", lines[0])
	}
	if len(lines) < 2 || !strings.Contains(lines[1], "abc") {
		t.Fatalf("bw attachment %q", out)
	}
	_ = att

	// A second account is invited, auto-accepted on a server without mail,
	// confirmed with the organization key, and can then read its collection.
	member := vwtest.NewAccount(ctx, t, "member")
	if err := admin.Invite(ctx, member.Email, vault.RoleUser, []vault.Grant{{Collection: "agents"}}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	_, phrase, err := admin.Confirm(ctx, member.Email, "")
	if err != nil {
		t.Fatalf("confirm, first step: %v", err)
	}
	// The phrase must be the one the member's own official client shows.
	if own := strings.TrimSpace(member.BW(ctx, t, `bw get fingerprint me --session "$S"`)); own != phrase {
		t.Fatalf("phrase %q, the member's client shows %q", phrase, own)
	}
	if _, _, err := admin.Confirm(ctx, member.Email, "wrong-phrase"); !errors.Is(err, vault.ErrFingerprintMismatch) {
		t.Fatalf("a wrong phrase must be refused: %v", err)
	}
	if _, _, err := admin.Confirm(ctx, member.Email, phrase); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// Vaultwarden reports managers as the custom type; a grants-only update
	// must keep the role, not turn it into owner.
	manager := vault.RoleManager
	if err := admin.UpdateMember(ctx, member.Email, &manager, nil); err != nil {
		t.Fatalf("make manager: %v", err)
	}
	if err := admin.UpdateMember(ctx, member.Email, nil, []vault.Grant{{Collection: "agents"}}); err != nil {
		t.Fatalf("update grants: %v", err)
	}
	if role, err := admin.MemberRole(ctx, member.Email); err != nil || role != vault.RoleManager {
		t.Fatalf("role after a grants-only update: %q, %v", role, err)
	}
	user := vault.RoleUser
	if err := admin.UpdateMember(ctx, member.Email, &user, nil); err != nil {
		t.Fatal(err)
	}
	mv := open(t, member)
	msnap, err := mv.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(msnap.Collections) != 1 || msnap.Collections[0].Name != "agents" {
		t.Fatalf("member collections %+v", msnap.Collections)
	}
	if _, err := msnap.Item(vault.ItemRef{Ref: "API_TOKEN", Collection: "agents"}); err != nil {
		t.Fatalf("member cannot read its item: %v", err)
	}
	if _, err := msnap.Collection("infra"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("member must not see infra: %v", err)
	}

	if _, err := v.Trash(ctx, vault.ItemRef{Ref: it.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Restore(ctx, vault.ItemRef{Ref: it.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.DeleteCollection(ctx, "agents"); !errors.Is(err, vault.ErrInvalid) {
		t.Fatalf("a non-empty collection must not be deleted: %v", err)
	}
	events, err := admin.Events(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Minute), 50)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	t.Logf("%d events, first %+v", len(events), events[:min(1, len(events))])
}
