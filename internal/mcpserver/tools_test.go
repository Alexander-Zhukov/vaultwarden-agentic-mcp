package mcpserver_test

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/fakevw"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

func TestPermanentDeleteRefusesAmbiguity(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	h.enablePermanentDelete(t)
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "db", "password": "p1"}, "")
	call(ctx, t, op, "delete_item", map[string]any{"item": "db"}, "")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "db", "password": "p2"}, "")
	call(ctx, t, op, "delete_item", map[string]any{"item": "db", "permanent": true}, "a live item")
	if live := items(call(ctx, t, op, "list_items", nil, ""), "items"); len(live) != 1 {
		t.Fatalf("the live item was touched: %v", live)
	}
}

func TestHiddenFieldStaysHidden(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{
		"collections": []string{"infra"}, "name": "K",
		"fields": []map[string]any{{"name": "api_token", "value": "OLD-SECRET", "kind": "hidden"}},
	}, "")
	call(ctx, t, op, "update_item", map[string]any{"item": "K", "set_fields": []map[string]any{{"name": "api_token", "value": "NEW-SECRET"}}}, "")
	item := call(ctx, t, op, "get_item", map[string]any{"item": "K"}, "")
	for _, f := range item["fields"].([]any) {
		if fm := f.(map[string]any); fm["name"] == "api_token" && (fm["kind"] != "hidden" || fm["value"] != nil) {
			t.Fatalf("hidden field became visible: %v", fm)
		}
	}
	if changes := item["password_changes"].([]any); len(changes) != 1 {
		t.Fatalf("the old hidden value is not in the history: %v", changes)
	}
}

func TestCaseOnlyRenameAndLoginFields(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "db", "password": "p"}, "")
	call(ctx, t, op, "update_item", map[string]any{"item": "db", "name": "DB"}, "")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "N", "type": "note", "username": "u"}, "belong to login items")
}

func TestLinksSurviveStrayRequests(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "K", "password": "value-123"}, "")
	link := call(ctx, t, op, "issue_value_link", map[string]any{"item": "K"}, "")["url"].(string)
	if code, _ := fetch(t, http.MethodHead, link, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD answered %d", code)
	}
	upload := call(ctx, t, op, "request_value_upload", map[string]any{"item": "K"}, "")["url"].(string)
	if code, _ := fetch(t, http.MethodPut, link, "x"); code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT on a value link answered %d", code)
	}
	downloadPath := h.url + "/v1/links/" + upload[len(h.url+"/v1/upload/"):]
	if code, _ := fetch(t, http.MethodGet, downloadPath, ""); code != http.StatusGone {
		t.Fatalf("an upload token served a download: %d", code)
	}
	if code, v := fetch(t, http.MethodGet, link, ""); code != http.StatusOK || v != "value-123" {
		t.Fatalf("stray requests spent the value link: %d", code)
	}
	if code, _ := fetch(t, http.MethodPut, upload, "new-value-1"); code != http.StatusOK {
		t.Fatalf("stray requests spent the upload link: %d", code)
	}
}

func TestLinkSourcesAreEnforced(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fake := fakevw.New(t)
	owner := fake.AddAccount("owner@example.test", "owner-pw")
	fake.AddOrganization(owner, "Machine", "infra")
	h := start(t, setup{
		serverURL: fake.URL(), mode: config.ModeConsumer,
		creds:   vault.Credentials{ClientID: owner.ClientID, ClientSecret: config.Secret(owner.ClientSecret), Password: config.Secret(owner.Password)},
		sources: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	})
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "K", "password": "value-123"}, "")
	link := call(ctx, t, op, "issue_value_link", map[string]any{"item": "K"}, "")["url"].(string)
	if code, _ := fetch(t, http.MethodGet, link, ""); code != http.StatusGone {
		t.Fatalf("a link was served outside its sources: %d", code)
	}
}

func TestShareRevokeIsPerClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"agents"}, "name": "K", "password": "value-123"}, "")
	share := call(ctx, t, op, "share_with_human", map[string]any{"item": "K"}, "")
	narrow := h.session(ctx, "narrow")
	call(ctx, t, narrow, "revoke_share", map[string]any{"share_id": share["share_id"]}, "not created by this client")
	call(ctx, t, op, "revoke_share", map[string]any{"share_id": share["share_id"]}, "")
}

func TestFindByValueIsRateLimited(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	call(ctx, t, op, "find_by_value", map[string]any{"value": "short"}, "shorter than")
	for i := 1; i < 30; i++ {
		call(ctx, t, op, "find_by_value", map[string]any{"value": "long-enough-value"}, "")
	}
	call(ctx, t, op, "find_by_value", map[string]any{"value": "long-enough-value"}, "a minute")
}

func TestReadOnlyInstanceHasNoWriteTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fake := fakevw.New(t)
	owner := fake.AddAccount("owner@example.test", "owner-pw")
	fake.AddOrganization(owner, "Machine", "infra")
	h := start(t, setup{
		serverURL: fake.URL(), mode: config.ModeAdmin, readOnly: true,
		creds: vault.Credentials{ClientID: owner.ClientID, ClientSecret: config.Secret(owner.ClientSecret), Password: config.Secret(owner.Password)},
	})
	names := toolNames(ctx, t, h.session(ctx, "op"))
	for _, write := range []string{
		"create_item", "update_item", "delete_item", "request_value_upload", "share_with_human",
		"invite_member", "confirm_member", "create_collection", "set_item_collections", "change_member",
	} {
		if slices.Contains(names, write) {
			t.Fatalf("%s is registered on a read-only instance", write)
		}
	}
	for _, read := range []string{"list_items", "issue_value_link", "list_members", "list_events"} {
		if !slices.Contains(names, read) {
			t.Fatalf("%s is missing", read)
		}
	}
}

func TestWriteSurvivesFailedResync(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, fake, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	call(ctx, t, op, "list_items", nil, "")
	// The create syncs before writing and again after; the second fails.
	fake.FailSync(2)
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "K", "password": "p"}, "")
	if list := items(call(ctx, t, op, "list_items", nil, ""), "items"); len(list) != 1 {
		t.Fatalf("the created item is not visible after the failed sync: %v", list)
	}
}

func TestFailedUploadLeavesNoSlot(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, fake, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")
	created := call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "K", "password": "p"}, "")
	id := created["item"].(map[string]any)["id"].(string)
	fake.FailNextUpload()
	call(ctx, t, op, "add_attachment", map[string]any{"item": "K", "file_name": "f", "text": "x"}, "upload")
	if n := fake.Attachments(id); n != 0 {
		t.Fatalf("a failed upload left %d attachment slots", n)
	}
}

func TestEveryToolIsAnnotated(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeAdmin, true)
	res, err := h.session(ctx, "op").ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil || a.OpenWorldHint == nil {
			t.Fatalf("%s has no annotations", tool.Name)
		}
		// Destructive and open-world together is the fallback for a tool
		// missing from the class table.
		if a.DestructiveHint != nil && *a.DestructiveHint && *a.OpenWorldHint {
			t.Fatalf("%s is missing from the tool class table", tool.Name)
		}
		if a.ReadOnlyHint == (a.DestructiveHint != nil) {
			t.Fatalf("%s: a tool is either read-only or says whether it is destructive", tool.Name)
		}
	}
	if len(res.Tools) < 30 {
		t.Fatalf("expected the full admin surface, got %d tools", len(res.Tools))
	}
}
