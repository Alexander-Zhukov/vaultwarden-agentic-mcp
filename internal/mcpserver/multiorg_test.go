package mcpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// TestAdminSeveralOrganizations covers an account that owns two
// organizations: admin tools need the organization, collections carry it, an
// item moves only within its own, and VWMCP_ORGANIZATION narrows what is
// managed.
func TestAdminSeveralOrganizations(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, fake, owner := fakeHarness(t, config.ModeAdmin, false)
	fake.AddOrganization(owner, "Lab", "experiments")
	op := h.session(ctx, "op")

	orgs := call(ctx, t, op, "list_organizations", nil, "")["organizations"].([]any)
	if len(orgs) != 2 {
		t.Fatalf("organizations %v", orgs)
	}
	for _, o := range orgs {
		m := o.(map[string]any)
		if m["managed"] != true || m["role"] != "owner" || m["members"].(float64) != 1 {
			t.Fatalf("organization %v", m)
		}
	}

	call(ctx, t, op, "list_members", nil, "manages several organizations (Lab, Machine)")
	lab := call(ctx, t, op, "list_members", map[string]any{"organization": "lab"}, "")
	if lab["organization"] != "Lab" || len(lab["members"].([]any)) != 1 {
		t.Fatalf("lab members %v", lab)
	}
	call(ctx, t, op, "list_members", map[string]any{"organization": "Nowhere"}, "not found")

	call(ctx, t, op, "create_collection", map[string]any{"name": "shared"}, "pass organization")
	call(ctx, t, op, "create_collection", map[string]any{"organization": "Lab", "name": "shared"}, "")
	call(ctx, t, op, "create_collection", map[string]any{"organization": "Machine", "name": "shared"}, "")

	byOrg := map[string][]string{}
	for _, c := range call(ctx, t, op, "list_collections", nil, "")["collections"].([]any) {
		m := c.(map[string]any)
		byOrg[m["organization"].(string)] = append(byOrg[m["organization"].(string)], m["name"].(string))
	}
	if len(byOrg["Lab"]) != 2 || len(byOrg["Machine"]) != 3 {
		t.Fatalf("collections by organization %v", byOrg)
	}
	only := call(ctx, t, op, "list_collections", map[string]any{"organization": "Lab"}, "")["collections"].([]any)
	if len(only) != 2 {
		t.Fatalf("lab collections %v", only)
	}

	// The item's organization decides; a collection of the other one is refused.
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"experiments"}, "name": "LAB_KEY", "password": "lab-secret"}, "")
	call(ctx, t, op, "set_item_collections", map[string]any{"item": "LAB_KEY", "collections": []string{"infra"}}, "cannot change organization")
	call(ctx, t, op, "create_item", map[string]any{"collections": []string{"infra"}, "name": "INFRA_KEY", "password": "p"}, "")

	// Narrowed to one organization: that one needs no argument, the other is refused.
	h.cfg.Organizations = []string{"Lab"}
	if got := call(ctx, t, op, "list_members", nil, "")["organization"]; got != "Lab" {
		t.Fatalf("narrowed default organization %v", got)
	}
	call(ctx, t, op, "list_members", map[string]any{"organization": "Machine"}, "not managed by this instance")
	call(ctx, t, op, "set_item_collections", map[string]any{"item": "INFRA_KEY", "collections": []string{"agents"}}, "not managed by this instance")
	managed := 0
	for _, o := range call(ctx, t, op, "list_organizations", nil, "")["organizations"].([]any) {
		if o.(map[string]any)["managed"] == true {
			managed++
		}
	}
	if managed != 1 {
		t.Fatalf("managed organizations %d", managed)
	}

	narrow := h.session(ctx, "narrow")
	call(ctx, t, narrow, "list_organizations", nil, "narrowed")
}
