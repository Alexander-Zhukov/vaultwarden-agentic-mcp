//go:build integration

package mcpserver_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwtest"
)

// TestLiveMCP drives the tools against a real Vaultwarden and checks with the
// official CLI that what the service wrote is what a human's client sees.
func TestLiveMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	owner := vwtest.NewAccount(ctx, t, "mcp")
	owner.NewOrganization(ctx, t, "Machine", "infra")
	h := start(t, setup{
		serverURL: vwtest.ServerURL(t), mode: config.ModeAdmin,
		creds: vault.Credentials{ClientID: owner.ClientID, ClientSecret: config.Secret(owner.ClientSecret), Password: config.Secret(owner.Password)},
	})
	op := h.session(ctx, "op")

	call(ctx, t, op, "create_collection", map[string]any{"name": "agents"}, "")
	call(ctx, t, op, "create_item", map[string]any{
		"collections": []string{"infra"}, "name": "CI_TOKEN", "generate_password": map[string]any{"length": 24},
	}, "")

	link := call(ctx, t, op, "issue_value_link", map[string]any{"item": "CI_TOKEN"}, "")
	status, value := fetch(t, http.MethodGet, link["url"].(string), "")
	if status != http.StatusOK || len(value) != 24 {
		t.Fatalf("link returned %d, %d bytes", status, len(value))
	}
	if got := owner.BW(ctx, t, `bw get password CI_TOKEN --session "$S"`); got != value {
		t.Fatal("the link and the official client disagree on the value")
	}

	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"agents"}, "name": "HASS_TOKEN"}, "")
	up := call(ctx, t, op, "request_value_upload", map[string]any{"item": "HASS_TOKEN"}, "")
	if code, _ := fetch(t, http.MethodPut, up["url"].(string), "uploaded-secret\n"); code != http.StatusOK {
		t.Fatalf("upload %d", code)
	}
	if got := owner.BW(ctx, t, `bw get password HASS_TOKEN --session "$S"`); got != "uploaded-secret" {
		t.Fatalf("bw sees %q after upload", got)
	}

	file := call(ctx, t, op, "request_value_upload", map[string]any{"item": "HASS_TOKEN", "attachment": "id_ed25519"}, "")
	if code, _ := fetch(t, http.MethodPut, file["url"].(string), "PRIVATE KEY"); code != http.StatusOK {
		t.Fatalf("file upload %d", code)
	}
	if got := owner.BW(ctx, t, `bw get attachment id_ed25519 --itemid "$(bw get item HASS_TOKEN --session "$S" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d).id))')" --output /tmp/f --session "$S" >&2; cat /tmp/f`); got != "PRIVATE KEY" {
		t.Fatalf("bw reads the attachment as %q", got)
	}

	call(ctx, t, op, "update_item", map[string]any{"item": "CI_TOKEN", "generate_password": map[string]any{}}, "")
	hist := owner.BW(ctx, t, `bw get item CI_TOKEN --session "$S" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d).passwordHistory[0].password))'`)
	if strings.TrimSpace(hist) != value {
		t.Fatal("rotation did not keep the previous password in the history")
	}

	share := call(ctx, t, op, "share_with_human", map[string]any{"item": "CI_TOKEN"}, "")
	if !strings.Contains(share["url"].(string), "/#/send/") {
		t.Fatalf("share %v", share)
	}
}

// TestLiveServerMode administers a real Vaultwarden through its admin panel.
// The test server is shared with other live tests, so everything is looked up
// by the names this test created.
func TestLiveServerMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	token := vwtest.AdminToken(t)
	owner := vwtest.NewAccount(ctx, t, "srvowner")
	other := vwtest.NewAccount(ctx, t, "srvother")
	orgName := "Doomed-" + strings.TrimSuffix(strings.TrimPrefix(owner.Email, "srvowner-"), "@example.test")
	owner.NewOrganization(ctx, t, orgName, "stuff")
	h := start(t, setup{serverURL: vwtest.ServerURL(t), mode: config.ModeServer, adminToken: token, permanentDelete: true})
	op := h.session(ctx, "op")

	status := call(ctx, t, op, "get_status", nil, "")
	if !strings.HasPrefix(status["server_version"].(string), "Vaultwarden, API 20") {
		t.Fatalf("status %v", status)
	}
	got := call(ctx, t, op, "get_user", map[string]any{"user": owner.Email}, "")
	orgs := got["organizations"].([]any)
	if got["status"] != "active" || len(orgs) != 1 || orgs[0].(map[string]any)["role"] != "owner" || orgs[0].(map[string]any)["status"] != "confirmed" {
		t.Fatalf("owner %v", got)
	}
	if byID := call(ctx, t, op, "get_user", map[string]any{"user": got["id"]}, ""); byID["email"] != owner.Email {
		t.Fatalf("by id %v", byID)
	}
	if found := items(call(ctx, t, op, "list_users", map[string]any{"query": other.Email}, ""), "users"); len(found) != 1 {
		t.Fatalf("list %v", found)
	}

	disabled := call(ctx, t, op, "change_user", map[string]any{"user": other.Email, "action": "disable"}, "")
	if disabled["user"].(map[string]any)["status"] != "disabled" {
		t.Fatalf("disable %v", disabled)
	}
	enabled := call(ctx, t, op, "change_user", map[string]any{"user": other.Email, "action": "enable"}, "")
	if enabled["user"].(map[string]any)["status"] != "active" {
		t.Fatalf("enable %v", enabled)
	}
	call(ctx, t, op, "change_user", map[string]any{"user": other.Email, "action": "deauthorize"}, "")

	newcomer := "srvnew-" + strings.TrimPrefix(other.Email, "srvother-")
	if inv := call(ctx, t, op, "invite_user", map[string]any{"email": newcomer}, ""); inv["user"].(map[string]any)["status"] != "invited" {
		t.Fatalf("invite %v", inv)
	}
	call(ctx, t, op, "change_user", map[string]any{"user": newcomer, "action": "resend_invite"}, "")
	call(ctx, t, op, "delete_user", map[string]any{"user": newcomer, "confirm": newcomer}, "")
	call(ctx, t, op, "get_user", map[string]any{"user": newcomer}, "not found")

	call(ctx, t, op, "delete_user", map[string]any{"user": owner.Email, "confirm": owner.Email}, "only owner")
	call(ctx, t, op, "delete_organization", map[string]any{"organization": orgName, "confirm": orgName}, "")
	for _, o := range items(call(ctx, t, op, "list_organizations", nil, ""), "organizations") {
		if o.(map[string]any)["name"] == orgName {
			t.Fatalf("%s survived its deletion", orgName)
		}
	}
	call(ctx, t, op, "delete_user", map[string]any{"user": owner.Email, "confirm": owner.Email}, "")
}

// TestLiveSeveralOrganizations manages two organizations of one account and
// checks with the official CLI that each collection landed in its own.
func TestLiveSeveralOrganizations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	owner := vwtest.NewAccount(ctx, t, "orgs")
	machine := owner.NewOrganization(ctx, t, "Machine", "infra")
	lab := owner.NewOrganization(ctx, t, "Lab", "experiments")
	h := start(t, setup{
		serverURL: vwtest.ServerURL(t), mode: config.ModeAdmin,
		creds: vault.Credentials{ClientID: owner.ClientID, ClientSecret: config.Secret(owner.ClientSecret), Password: config.Secret(owner.Password)},
	})
	op := h.session(ctx, "op")

	if orgs := call(ctx, t, op, "list_organizations", nil, "")["organizations"].([]any); len(orgs) != 2 {
		t.Fatalf("organizations %v", orgs)
	}
	call(ctx, t, op, "create_collection", map[string]any{"name": "shared"}, "pass organization")
	call(ctx, t, op, "create_collection", map[string]any{"organization": "Lab", "name": "shared"}, "")

	for _, c := range []struct {
		id   string
		want string
	}{{lab.ID, "experiments,shared"}, {machine.ID, "infra"}} {
		got := owner.BW(ctx, t, `bw list org-collections --organizationid `+c.id+` --session "$S" | node -e 'let d="";process.stdin.on("data",x=>d+=x).on("end",()=>console.log(JSON.parse(d).map(c=>c.name).sort().join(",")))'`)
		if strings.TrimSpace(got) != c.want {
			t.Fatalf("organization %s holds %q, want %q", c.id, got, c.want)
		}
	}
}
