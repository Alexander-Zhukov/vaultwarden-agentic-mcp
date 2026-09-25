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
