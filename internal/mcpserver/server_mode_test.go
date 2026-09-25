package mcpserver_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/fakevw"
)

// serverHarness is a server with an organization Machine (owner, a confirmed
// manager, an invited member the panel does not list) and an organization
// Lonely whose only confirmed member is a user.
func serverHarness(t *testing.T, readOnly, permanentDelete bool) (*harness, *fakevw.Server) {
	t.Helper()
	fake := fakevw.New(t)
	fake.EnableAdmin("panel-token")
	owner := fake.AddAccount("owner@example.test", "owner-pw")
	orgID, _ := fake.AddOrganization(owner, "Machine", "infra")
	member := fake.AddAccount("member@example.test", "member-pw")
	fake.AddMember(orgID, member, bitwarden.MemberManager, bitwarden.MemberConfirmed)
	pending := fake.AddAccount("pending@example.test", "pending-pw")
	fake.AddMember(orgID, pending, bitwarden.MemberUser, bitwarden.MemberAccepted)
	loner := fake.AddAccount("loner@example.test", "loner-pw")
	lonelyID, _ := fake.AddOrganization(loner, "Lonely", "things")
	fake.AddMember(lonelyID, pending, bitwarden.MemberUser, bitwarden.MemberInvited)
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
	if status["mode"] != "server" || status["users"].(float64) != 4 || status["organizations"].(float64) != 2 ||
		status["server_version"] != "Vaultwarden 1.36.0 (API 2025.12.0)" {
		t.Fatalf("status %v", status)
	}

	if got := items(call(ctx, t, op, "list_users", nil, ""), "users"); len(got) != 4 {
		t.Fatalf("users %v", got)
	}
	if got := items(call(ctx, t, op, "list_users", map[string]any{"query": "MEMBER"}, ""), "users"); len(got) != 1 {
		t.Fatalf("query %v", got)
	}
	call(ctx, t, op, "list_users", map[string]any{"status": "gone"}, "want active, invited or disabled")
	// The accepted member is not a confirmed one, so the panel does not list it.
	if got := items(call(ctx, t, op, "list_users", map[string]any{"organization": "machine"}, ""), "users"); len(got) != 2 {
		t.Fatalf("confirmed members of Machine %v", got)
	}

	u := call(ctx, t, op, "get_user", map[string]any{"user": "MEMBER@example.test"}, "")
	orgs := u["organizations"].([]any)
	if u["status"] != "active" || u["last_active"] == nil || len(orgs) != 1 || orgs[0].(map[string]any)["role"] != "manager" {
		t.Fatalf("user %v", u)
	}
	if !strings.HasSuffix(u["created"].(string), "Z") {
		t.Fatalf("created is not shown in the configured zone: %v", u["created"])
	}
	call(ctx, t, op, "get_user", map[string]any{"user": "nobody@example.test"}, "not found")

	byName := map[string]map[string]any{}
	for _, o := range items(call(ctx, t, op, "list_organizations", nil, ""), "organizations") {
		byName[o.(map[string]any)["name"].(string)] = o.(map[string]any)
	}
	if m := byName["Machine"]; m["members"].(float64) != 2 || !slices.Equal(m["owners"].([]any), []any{"owner@example.test"}) {
		t.Fatalf("organizations %v", byName)
	}

	invited := call(ctx, t, op, "invite_user", map[string]any{"email": "new@example.test"}, "")
	if user := invited["user"].(map[string]any); user["status"] != "invited" || user["id"] == "" {
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
	if got := items(call(ctx, t, op, "list_users", map[string]any{"status": "disabled"}, ""), "users"); len(got) != 1 {
		t.Fatalf("disabled users %v", got)
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

	call(ctx, t, op, "delete_user", map[string]any{"user": "owner@example.test"}, "only confirmed owner")
	call(ctx, t, op, "delete_user", map[string]any{"user": "loner@example.test"}, "only confirmed owner")

	// The code the first call issues is the only way through; knowing the
	// target is not enough.
	preview := call(ctx, t, op, "delete_user", map[string]any{"user": "new@example.test"}, "")
	code, _ := preview["confirm"].(string)
	if preview["deleted"] != false || len(code) != 32 {
		t.Fatalf("delete preview %v", preview)
	}
	call(ctx, t, op, "delete_user", map[string]any{"user": "new@example.test", "confirm": "new@example.test"}, "not valid")
	call(ctx, t, op, "delete_user", map[string]any{"user": "member@example.test", "confirm": code}, "not valid")
	call(ctx, t, h.session(ctx, "ro"), "delete_user", map[string]any{"user": "new@example.test", "confirm": code}, "read-only")
	if done := call(ctx, t, op, "delete_user", map[string]any{"user": "new@example.test", "confirm": code}, ""); done["deleted"] != true {
		t.Fatalf("delete %v", done)
	}
	call(ctx, t, op, "get_user", map[string]any{"user": "new@example.test"}, "not found")

	machine := call(ctx, t, op, "delete_organization", map[string]any{"organization": "machine"}, "")
	if machine["deleted"] != false || len(machine["members"].([]any)) != 2 {
		t.Fatalf("organization preview %v", machine)
	}
	call(ctx, t, op, "delete_organization", map[string]any{"organization": "Machine", "confirm": "Machine"}, "not valid")
	call(ctx, t, op, "delete_organization", map[string]any{"organization": "Nowhere"}, "not found")
	call(ctx, t, op, "delete_organization", map[string]any{"organization": ""}, "required")
	if done := call(ctx, t, op, "delete_organization", map[string]any{"organization": "Machine", "confirm": machine["confirm"]}, ""); done["deleted"] != true {
		t.Fatalf("organization delete %v", done)
	}
	call(ctx, t, op, "delete_organization", map[string]any{"organization": "Machine", "confirm": machine["confirm"]}, "not found")

	// An organization whose last confirmed member leaves is reached by id.
	lonelyID := byName["Lonely"]["id"].(string)
	call(ctx, t, op, "change_user", map[string]any{"user": "loner@example.test", "action": "disable"}, "")
	byID := call(ctx, t, op, "delete_organization", map[string]any{"organization": lonelyID}, "")
	if byID["id"] != lonelyID || byID["name"] != "Lonely" {
		t.Fatalf("lonely preview %v", byID)
	}
	if done := call(ctx, t, op, "delete_organization", map[string]any{"organization": lonelyID, "confirm": byID["confirm"]}, ""); done["deleted"] != true {
		t.Fatalf("lonely delete %v", done)
	}
	unlisted := call(ctx, t, op, "delete_organization", map[string]any{"organization": "00000000-0000-4000-8000-000000000000"}, "")
	if unlisted["note"] == nil {
		t.Fatalf("unlisted preview %v", unlisted)
	}
	call(ctx, t, op, "delete_organization", map[string]any{"organization": "00000000-0000-4000-8000-000000000000", "confirm": unlisted["confirm"]}, "doesn't exist")

	call(ctx, t, h.session(ctx, "narrow"), "list_users", nil, "narrowed")
	call(ctx, t, h.session(ctx, "ro"), "change_user", map[string]any{"user": "member@example.test", "action": "disable"}, "read-only")
}

// TestServerModeSwitches keeps the tools of a disabled capability away.
func TestServerModeSwitches(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name             string
		readOnly, delete bool
		absent           []string
	}{
		{"read-only", true, false, []string{"invite_user", "change_user", "delete_user", "delete_organization"}},
		{"write without delete", false, false, []string{"delete_user", "delete_organization"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			h, _ := serverHarness(t, tt.readOnly, tt.delete)
			names := toolNames(ctx, t, h.session(ctx, "op"))
			for _, name := range tt.absent {
				if slices.Contains(names, name) {
					t.Fatalf("%s registered: %v", name, names)
				}
			}
		})
	}
}

// TestServerModeWrongToken reports the refused token and does not try again
// on every call.
func TestServerModeWrongToken(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fake := fakevw.New(t)
	fake.EnableAdmin("right")
	h := start(t, setup{serverURL: fake.URL(), mode: config.ModeServer, adminToken: "wrong"})
	op := h.session(ctx, "op")
	call(ctx, t, op, "list_users", nil, "admin token was refused")
	call(ctx, t, op, "list_users", nil, "next login attempt in")
}
