package mcpserver_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/fakevw"
)

func serverHarness(t *testing.T, readOnly, permanentDelete bool) (*harness, *fakevw.Server) {
	t.Helper()
	fake := fakevw.New(t)
	fake.EnableAdmin("panel-token")
	owner := fake.AddAccount("owner@example.test", "owner-pw")
	orgID, _ := fake.AddOrganization(owner, "Machine", "infra")
	member := fake.AddAccount("member@example.test", "member-pw")
	fake.AddMember(orgID, member, bitwarden.MemberUser)
	h := start(t, setup{
		serverURL: fake.URL(), mode: config.ModeServer, adminToken: "panel-token",
		readOnly: readOnly, permanentDelete: permanentDelete,
	})
	return h, fake
}

// TestServerMode administers the server's accounts and organizations through
// the admin panel.
func TestServerMode(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, fake := serverHarness(t, false, true)
	h.cfg.Caps.InviteDomains = []string{"example.test"}
	op := h.session(ctx, "op")

	names := toolNames(ctx, t, op)
	for _, absent := range []string{"list_items", "get_item", "issue_value_link", "list_members", "create_item"} {
		if slices.Contains(names, absent) {
			t.Fatalf("%s must not exist in server mode: %v", absent, names)
		}
	}
	status := call(ctx, t, op, "get_status", nil, "")
	if status["mode"] != "server" || status["users"].(float64) != 2 || status["organizations"].(float64) != 1 || status["server_version"] != "Vaultwarden, API 2025.12.0" {
		t.Fatalf("status %v", status)
	}

	users := items(call(ctx, t, op, "list_users", nil, ""), "users")
	if len(users) != 2 {
		t.Fatalf("users %v", users)
	}
	if got := items(call(ctx, t, op, "list_users", map[string]any{"query": "MEMBER"}, ""), "users"); len(got) != 1 {
		t.Fatalf("query %v", got)
	}
	call(ctx, t, op, "list_users", map[string]any{"status": "gone"}, "want active, invited or disabled")
	if got := items(call(ctx, t, op, "list_users", map[string]any{"organization": "machine"}, ""), "users"); len(got) != 2 {
		t.Fatalf("members of Machine %v", got)
	}

	u := call(ctx, t, op, "get_user", map[string]any{"user": "member@example.test"}, "")
	orgs := u["organizations"].([]any)
	if u["status"] != "active" || len(orgs) != 1 || orgs[0].(map[string]any)["role"] != "user" {
		t.Fatalf("user %v", u)
	}
	call(ctx, t, op, "get_user", map[string]any{"user": "nobody@example.test"}, "not found")

	org := items(call(ctx, t, op, "list_organizations", nil, ""), "organizations")[0].(map[string]any)
	if org["name"] != "Machine" || org["members"].(float64) != 2 || !slices.Equal(org["owners"].([]any), []any{"owner@example.test"}) {
		t.Fatalf("organization %v", org)
	}

	invited := call(ctx, t, op, "invite_user", map[string]any{"email": "new@example.test"}, "")
	if invited["user"].(map[string]any)["status"] != "invited" {
		t.Fatalf("invite %v", invited)
	}
	call(ctx, t, op, "invite_user", map[string]any{"email": "someone@elsewhere.test"}, "outside the domains")
	call(ctx, t, op, "invite_user", map[string]any{"email": "new@example.test"}, "already exists")
	call(ctx, t, op, "change_user", map[string]any{"user": "new@example.test", "action": "resend_invite"}, "")
	call(ctx, t, op, "change_user", map[string]any{"user": "member@example.test", "action": "resend_invite"}, "already registered")

	disabled := call(ctx, t, op, "change_user", map[string]any{"user": "member@example.test", "action": "disable"}, "")
	if disabled["user"].(map[string]any)["status"] != "disabled" {
		t.Fatalf("disable %v", disabled)
	}
	call(ctx, t, op, "change_user", map[string]any{"user": "member@example.test", "action": "enable"}, "")
	call(ctx, t, op, "change_user", map[string]any{"user": "member@example.test", "action": "deauthorize"}, "")
	call(ctx, t, op, "change_user", map[string]any{"user": "member@example.test", "action": "explode"}, "want disable")

	// An expired session is renewed once, transparently.
	logins := fake.AdminLogins()
	fake.ExpireAdminSessions()
	call(ctx, t, op, "get_user", map[string]any{"user": "owner@example.test"}, "")
	if fake.AdminLogins() != logins+1 {
		t.Fatalf("logins %d after expiry, had %d", fake.AdminLogins(), logins)
	}

	call(ctx, t, op, "delete_user", map[string]any{"user": "owner@example.test"}, "only owner")
	preview := call(ctx, t, op, "delete_user", map[string]any{"user": "new@example.test"}, "")
	if preview["deleted"] != false || preview["next"] == nil {
		t.Fatalf("delete preview %v", preview)
	}
	call(ctx, t, op, "delete_user", map[string]any{"user": "new@example.test", "confirm": "other@example.test"}, "does not match")
	if done := call(ctx, t, op, "delete_user", map[string]any{"user": "new@example.test", "confirm": "new@example.test"}, ""); done["deleted"] != true {
		t.Fatalf("delete %v", done)
	}
	call(ctx, t, op, "get_user", map[string]any{"user": "new@example.test"}, "not found")

	orgPreview := call(ctx, t, op, "delete_organization", map[string]any{"organization": "machine"}, "")
	if orgPreview["deleted"] != false || len(orgPreview["members"].([]any)) != 2 {
		t.Fatalf("organization preview %v", orgPreview)
	}
	call(ctx, t, op, "delete_organization", map[string]any{"organization": "Machine", "confirm": "machine"}, "does not match")
	call(ctx, t, op, "delete_organization", map[string]any{"organization": "Nowhere"}, "not found")
	call(ctx, t, op, "delete_organization", map[string]any{"organization": ""}, "required")
	if done := call(ctx, t, op, "delete_organization", map[string]any{"organization": "Machine", "confirm": "Machine"}, ""); done["deleted"] != true {
		t.Fatalf("organization delete %v", done)
	}
	if got := items(call(ctx, t, op, "list_organizations", nil, ""), "organizations"); len(got) != 0 {
		t.Fatalf("organizations after delete %v", got)
	}

	call(ctx, t, h.session(ctx, "narrow"), "list_users", nil, "narrowed")
	call(ctx, t, h.session(ctx, "ro"), "change_user", map[string]any{"user": "member@example.test", "action": "disable"}, "read-only")
}

// TestServerModeSwitches keeps the tools of a disabled capability away.
func TestServerModeSwitches(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tt := range []struct {
		readOnly, delete bool
		absent           []string
	}{
		{true, false, []string{"invite_user", "change_user", "delete_user", "delete_organization"}},
		{false, false, []string{"delete_user", "delete_organization"}},
	} {
		h, _ := serverHarness(t, tt.readOnly, tt.delete)
		names := toolNames(ctx, t, h.session(ctx, "op"))
		for _, name := range tt.absent {
			if slices.Contains(names, name) {
				t.Fatalf("%s registered with write=%v delete=%v: %v", name, !tt.readOnly, tt.delete, names)
			}
		}
	}
}

// TestServerModeWrongToken reports the refused token instead of hanging.
func TestServerModeWrongToken(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fake := fakevw.New(t)
	fake.EnableAdmin("right")
	h := start(t, setup{serverURL: fake.URL(), mode: config.ModeServer, adminToken: "wrong"})
	call(ctx, t, h.session(ctx, "op"), "list_users", nil, "admin token refused")
}
