package mcpserver_test

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/fakevw"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

func fakeHarness(t *testing.T, mode config.Mode, reveal bool) (*harness, *fakevw.Server, *fakevw.Account) {
	t.Helper()
	fake := fakevw.New(t)
	owner := fake.AddAccount("owner@example.test", "owner-pw")
	fake.AddOrganization(owner, "Machine", "infra", "agents")
	h := start(t, setup{
		serverURL: fake.URL(), mode: mode, reveal: reveal,
		creds: vault.Credentials{ClientID: owner.ClientID, ClientSecret: config.Secret(owner.ClientSecret), Password: config.Secret(owner.Password)},
	})
	return h, fake, owner
}

// TestToolsEndToEnd walks every consumer tool over real HTTP, through the
// authentication middleware, against the fake server.
func TestToolsEndToEnd(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, false)
	op := h.session(ctx, "op")

	names := toolNames(ctx, t, op)
	for _, absent := range []string{"get_secret", "get_attachment", "invite_member", "list_members"} {
		if slices.Contains(names, absent) {
			t.Fatalf("%s must not be registered: %v", absent, names)
		}
	}
	status := call(ctx, t, op, "get_status", nil, "")
	if status["client"] != "op" || status["allow_reveal"] != false || status["links_enabled"] != true {
		t.Fatalf("status %v", status)
	}

	created := call(ctx, t, op, "create_item", map[string]any{
		"collections": []string{"infra"}, "name": "CI_TOKEN", "notes": "no convention",
		"generate_password": map[string]any{"length": 24}, "expires": time.Now().Add(48 * time.Hour).Format(time.DateOnly),
		"uris": []string{"https://ci.example.test"}, "username": "ci-bot",
		"fields": []map[string]any{{"name": "client_secret", "value": "HIDDEN-VALUE", "kind": "hidden"}, {"name": "region", "value": "eu"}},
	}, "")
	raw, _ := json.Marshal(created)
	if created["generated_password"] != true || created["warnings"] == nil || strings.Contains(string(raw), "HIDDEN-VALUE") {
		t.Fatalf("create %s", raw)
	}
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "ci_token"}, "already has an item")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"nope"}, "name": "X"}, "not found")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "X", "password": "a", "upload": true}, "at most one")

	link := call(ctx, t, op, "issue_value_link", map[string]any{"item": "CI_TOKEN"}, "")
	code, value := fetch(t, http.MethodGet, link["url"].(string), "")
	if code != http.StatusOK || len(value) != 24 {
		t.Fatalf("link %d %q", code, value)
	}
	if again, _ := fetch(t, http.MethodGet, link["url"].(string), ""); again != http.StatusGone {
		t.Fatalf("second fetch %d", again)
	}
	hidden := call(ctx, t, op, "issue_value_link", map[string]any{"item": "CI_TOKEN", "field": "field:client_secret"}, "")
	if _, v := fetch(t, http.MethodGet, hidden["url"].(string), ""); v != "HIDDEN-VALUE" {
		t.Fatalf("hidden field link %q", v)
	}
	call(ctx, t, op, "issue_value_link", map[string]any{"item": "CI_TOKEN", "field": "field:nope"}, "no value")

	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	call(ctx, t, op, "update_item", map[string]any{"item": "CI_TOKEN", "totp": seed}, "")
	totp := call(ctx, t, op, "issue_value_link", map[string]any{"item": "CI_TOKEN", "field": "totp"}, "")
	if _, code := fetch(t, http.MethodGet, totp["url"].(string), ""); len(code) != 6 {
		t.Fatalf("totp link returned %q", code)
	}

	up := call(ctx, t, op, "create_item", map[string]any{"collections": []string{"agents"}, "name": "HASS_TOKEN", "upload": true}, "")
	form, body := fetch(t, http.MethodGet, up["upload_url"].(string), "")
	if form != http.StatusOK || !strings.Contains(body, "HASS_TOKEN") || !strings.Contains(body, "<form") {
		t.Fatalf("form %d", form)
	}
	if code, _ := fetch(t, http.MethodPut, up["upload_url"].(string), "uploaded-secret\n"); code != http.StatusOK {
		t.Fatalf("upload %d", code)
	}
	if code, _ := fetch(t, http.MethodPut, up["upload_url"].(string), "again"); code != http.StatusGone {
		t.Fatalf("upload link reused: %d", code)
	}
	check := call(ctx, t, op, "issue_value_link", map[string]any{"item": "HASS_TOKEN"}, "")
	if _, v := fetch(t, http.MethodGet, check["url"].(string), ""); v != "uploaded-secret" {
		t.Fatalf("uploaded value reads back as %q", v)
	}

	file := call(ctx, t, op, "request_value_upload", map[string]any{"item": "HASS_TOKEN", "attachment": "id_ed25519"}, "")
	if code, _ := fetch(t, http.MethodPut, file["url"].(string), "PRIVATE KEY"); code != http.StatusOK {
		t.Fatalf("file upload %d", code)
	}
	dl := call(ctx, t, op, "issue_value_link", map[string]any{"item": "HASS_TOKEN", "attachment": "id_ed25519"}, "")
	if code, body := fetch(t, http.MethodGet, dl["url"].(string), ""); code != http.StatusOK || body != "PRIVATE KEY" {
		t.Fatalf("file download %d %q", code, body)
	}
	call(ctx, t, op, "add_attachment", map[string]any{"item": "HASS_TOKEN", "file_name": "notes.txt", "text": "hello"}, "")
	call(ctx, t, op, "add_attachment", map[string]any{"item": "HASS_TOKEN", "file_name": "x", "text": "a", "base64": "YQ=="}, "exactly one")
	call(ctx, t, op, "delete_attachment", map[string]any{"item": "HASS_TOKEN", "attachment": "notes.txt"}, "")

	item := call(ctx, t, op, "get_item", map[string]any{"item": "CI_TOKEN", "collection": "infra"}, "")
	raw, _ = json.Marshal(item)
	if strings.Contains(string(raw), value) || strings.Contains(string(raw), "HIDDEN-VALUE") || strings.Contains(string(raw), seed) {
		t.Fatalf("get_item leaks a value: %s", raw)
	}
	if fp, _ := item["fingerprints"].(map[string]any); fp["password"] == nil || fp["totp"] == nil {
		t.Fatalf("fingerprints %v", item["fingerprints"])
	}
	if list := items(call(ctx, t, op, "list_items", map[string]any{"collection": "infra"}, ""), "items"); len(list) != 1 {
		t.Fatalf("list %v", list)
	}
	if hits := items(call(ctx, t, op, "search_items", map[string]any{"query": "ci example"}, ""), "items"); len(hits) != 1 {
		t.Fatalf("search %v", hits)
	}
	if hits := items(call(ctx, t, op, "search_items", map[string]any{"query": "HIDDEN-VALUE"}, ""), "items"); len(hits) != 0 {
		t.Fatalf("search matched a secret: %v", hits)
	}
	if found := items(call(ctx, t, op, "find_by_value", map[string]any{"value": "uploaded-secret"}, ""), "items"); len(found) != 1 {
		t.Fatalf("find_by_value %v", found)
	}

	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"agents"}, "name": "COPY", "password": "uploaded-secret"}, "")
	if copies := items(call(ctx, t, op, "find_copies", map[string]any{"item": "HASS_TOKEN"}, ""), "copies"); len(copies) != 1 {
		t.Fatalf("copies %v", copies)
	}
	var found []string
	for _, i := range items(call(ctx, t, op, "check_items", nil, ""), "issues") {
		found = append(found, i.(map[string]any)["kind"].(string))
	}
	kinds := strings.Join(found, " ")
	for _, want := range []string{"expires_soon", "notes_format", "duplicate"} {
		if !strings.Contains(kinds, want) {
			t.Fatalf("check_items %s lacks %s", kinds, want)
		}
	}
	cols := items(call(ctx, t, op, "list_collections", nil, ""), "collections")
	if len(cols) != 2 {
		t.Fatalf("collections %v", cols)
	}

	share := call(ctx, t, op, "share_with_human", map[string]any{"item": "CI_TOKEN", "max_access": 2}, "")
	if !strings.Contains(share["url"].(string), "/#/send/") || share["max_access"] != float64(2) {
		t.Fatalf("share %v", share)
	}
	call(ctx, t, op, "share_with_human", map[string]any{"item": "CI_TOKEN", "field": "totp"}, "expires before")
	call(ctx, t, op, "revoke_share", map[string]any{"share_id": share["share_id"]}, "")

	rotated := call(ctx, t, op, "update_item", map[string]any{"item": "CI_TOKEN", "generate_password": map[string]any{}, "name": "CI_TOKEN_V2", "remove_fields": []string{"region"}}, "")
	if rotated["item"].(map[string]any)["name"] != "CI_TOKEN_V2" {
		t.Fatalf("update %v", rotated)
	}
	detail := call(ctx, t, op, "get_item", map[string]any{"item": "CI_TOKEN_V2"}, "")
	if len(detail["password_changes"].([]any)) != 1 {
		t.Fatalf("history %v", detail["password_changes"])
	}
	call(ctx, t, op, "update_item", map[string]any{"item": "CI_TOKEN_V2"}, "nothing to change")
	call(ctx, t, op, "update_item", map[string]any{"item": "CI_TOKEN_V2", "name": "COPY"}, "")
	call(ctx, t, op, "update_item", map[string]any{"item": "HASS_TOKEN", "name": "COPY"}, "already has an item")

	call(ctx, t, op, "delete_item", map[string]any{"item": "COPY", "collection": "agents", "permanent": true}, "disabled")
	gone := call(ctx, t, op, "issue_value_link", map[string]any{"item": "HASS_TOKEN"}, "")
	call(ctx, t, op, "delete_item", map[string]any{"item": "HASS_TOKEN"}, "")
	if code, _ := fetch(t, http.MethodGet, gone["url"].(string), ""); code != http.StatusGone {
		t.Fatalf("a link to a trashed item still works: %d", code)
	}
	if trash := items(call(ctx, t, op, "list_items", map[string]any{"trash": true}, ""), "items"); len(trash) != 1 {
		t.Fatalf("trash %v", trash)
	}
	call(ctx, t, op, "restore_item", map[string]any{"item": "HASS_TOKEN"}, "")

	ro := h.session(ctx, "ro")
	call(ctx, t, ro, "create_item", map[string]any{"collections": []string{"infra"}, "name": "X"}, "read-only")
	call(ctx, t, ro, "request_value_upload", map[string]any{"item": "HASS_TOKEN"}, "read-only")
	call(ctx, t, ro, "share_with_human", map[string]any{"item": "HASS_TOKEN"}, "read-only")
	call(ctx, t, ro, "issue_value_link", map[string]any{"item": "HASS_TOKEN"}, "")

	narrow := h.session(ctx, "narrow")
	for _, it := range items(call(ctx, t, narrow, "list_items", nil, ""), "items") {
		if cs := it.(map[string]any)["collections"].([]any); cs[0] != "agents" {
			t.Fatalf("narrow client sees %v", it)
		}
	}
	call(ctx, t, narrow, "get_item", map[string]any{"item": "CI_TOKEN_V2"}, "not found")
	call(ctx, t, narrow, "issue_value_link", map[string]any{"item": "CI_TOKEN_V2"}, "not found")
	call(ctx, t, narrow, "create_item", map[string]any{"collections": []string{"infra"}, "name": "X"}, "not found")
	if found := items(call(ctx, t, narrow, "find_by_value", map[string]any{"value": value}, ""), "items"); len(found) != 0 {
		t.Fatalf("narrow client found an item outside its collections: %v", found)
	}

	if code, _ := fetch(t, http.MethodPost, h.url+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d", code)
	}
}

func TestRevealInstance(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, _, _ := fakeHarness(t, config.ModeConsumer, true)
	op := h.session(ctx, "op")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "K", "password": "pw-1", "username": "u"}, "")
	got := call(ctx, t, op, "get_secret", map[string]any{"item": "K"}, "")
	if got["value"] != "pw-1" {
		t.Fatalf("get_secret %v", got)
	}
	call(ctx, t, op, "add_attachment", map[string]any{"item": "K", "file_name": "bin", "base64": "AP8="}, "")
	att := call(ctx, t, op, "get_attachment", map[string]any{"item": "K", "attachment": "bin"}, "")
	if att["base64"] != "AP8=" {
		t.Fatalf("get_attachment %v", att)
	}
}

func TestAdminTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, fake, _ := fakeHarness(t, config.ModeAdmin, false)
	op := h.session(ctx, "op")
	member := fake.AddAccount("member@example.test", "member-pw")

	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "INFRA_KEY", "password": "p"}, "")
	call(ctx, t, op, "create_collection", map[string]any{"name": "team"}, "")
	call(ctx, t, op, "create_collection", map[string]any{"name": "TEAM"}, "already exists")
	call(ctx, t, op, "invite_member", map[string]any{"email": member.Email, "role": "user", "collections": []map[string]any{{"collection": "team"}}}, "")
	call(ctx, t, op, "invite_member", map[string]any{"email": "not-an-email"}, "not an email")
	pending := call(ctx, t, op, "confirm_member", map[string]any{"member": member.Email}, "")
	phrase, _ := pending["fingerprint_phrase"].(string)
	if pending["status"] != "accepted" || strings.Count(phrase, "-") != 4 {
		t.Fatalf("first step %v", pending)
	}
	call(ctx, t, op, "confirm_member", map[string]any{"member": member.Email, "fingerprint_phrase": "wrong-words-for-this-key"}, "does not match")
	confirmed := call(ctx, t, op, "confirm_member", map[string]any{"member": member.Email, "fingerprint_phrase": phrase}, "")
	if confirmed["status"] != "confirmed" {
		t.Fatalf("confirm %v", confirmed)
	}
	call(ctx, t, op, "confirm_member", map[string]any{"member": member.Email, "fingerprint_phrase": phrase}, "only an accepted")
	call(ctx, t, op, "invite_member", map[string]any{"email": "boss@example.test", "role": "owner"}, "not handled here")

	var memberOf []string
	for _, m := range items(call(ctx, t, op, "list_members", nil, ""), "members") {
		mm := m.(map[string]any)
		if mm["email"] == member.Email {
			for _, c := range mm["collections"].([]any) {
				memberOf = append(memberOf, c.(map[string]any)["collection"].(string))
			}
		}
	}
	if !slices.Equal(memberOf, []string{"team"}) {
		t.Fatalf("member collections %v", memberOf)
	}

	call(ctx, t, op, "set_item_collections", map[string]any{"item": "INFRA_KEY", "collections": []string{"infra", "team"}}, "")
	call(ctx, t, op, "update_collection", map[string]any{"collection": "team", "name": "team-work", "members": []map[string]any{{"member": member.Email, "read_only": true}}}, "")
	cols := items(call(ctx, t, op, "list_collections", nil, ""), "collections")
	var renamed map[string]any
	for _, c := range cols {
		if c.(map[string]any)["name"] == "team-work" {
			renamed = c.(map[string]any)
		}
	}
	if renamed == nil || renamed["items"] != float64(1) || len(renamed["members"].([]any)) != 1 {
		t.Fatalf("collections %v", cols)
	}
	call(ctx, t, op, "delete_collection", map[string]any{"collection": "team-work"}, "still holds")
	call(ctx, t, op, "set_item_collections", map[string]any{"item": "INFRA_KEY", "collections": []string{"infra"}}, "")
	call(ctx, t, op, "delete_collection", map[string]any{"collection": "team-work"}, "")

	call(ctx, t, op, "update_member", map[string]any{"member": member.Email, "role": "manager"}, "")
	call(ctx, t, op, "update_member", map[string]any{"member": member.Email, "role": "admin"}, "not handled here")
	// A manager whose collections change stays a manager: the server reports
	// the role as the custom type, which must not turn into owner.
	call(ctx, t, op, "update_member", map[string]any{"member": member.Email, "collections": []map[string]any{{"collection": "infra"}}}, "")
	for _, m := range items(call(ctx, t, op, "list_members", nil, ""), "members") {
		if mm := m.(map[string]any); mm["email"] == member.Email && mm["role"] != "manager" {
			t.Fatalf("manager became %v", mm["role"])
		}
	}
	call(ctx, t, op, "update_member", map[string]any{"member": member.Email}, "nothing to change")
	call(ctx, t, op, "change_member", map[string]any{"member": member.Email, "action": "revoke"}, "")
	call(ctx, t, op, "change_member", map[string]any{"member": member.Email, "action": "restore"}, "")
	call(ctx, t, op, "change_member", map[string]any{"member": "owner@example.test", "action": "remove"}, "not handled here")
	call(ctx, t, op, "change_member", map[string]any{"member": member.Email, "action": "explode"}, "action")
	call(ctx, t, op, "change_member", map[string]any{"member": member.Email, "action": "remove"}, "")

	if events := items(call(ctx, t, op, "list_events", map[string]any{"since": "1h"}, ""), "events"); len(events) == 0 {
		t.Fatal("no events")
	}

	ro := h.session(ctx, "ro")
	call(ctx, t, ro, "create_collection", map[string]any{"name": "x"}, "read-only")
	call(ctx, t, ro, "list_members", nil, "")
	narrow := h.session(ctx, "narrow")
	call(ctx, t, narrow, "list_members", nil, "narrowed")
}
