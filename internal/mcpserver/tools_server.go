package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwadmin"
)

type serverMembershipView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role" jsonschema:"owner, admin, manager or user"`
}

type userView struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Name          string                 `json:"name,omitempty"`
	Status        string                 `json:"status" jsonschema:"active, invited (has not registered yet) or disabled"`
	TwoFactor     bool                   `json:"two_factor"`
	Created       string                 `json:"created,omitempty"`
	LastActive    string                 `json:"last_active,omitempty"`
	Organizations []serverMembershipView `json:"organizations,omitempty" jsonschema:"confirmed memberships only; the admin panel lists no others"`
}

func userStatus(u vwadmin.User) string {
	switch {
	case u.Disabled():
		return "disabled"
	case u.Status == vwadmin.StatusInvited:
		return "invited"
	default:
		return "active"
	}
}

func (s *server) toUserView(u vwadmin.User) userView {
	v := userView{ID: u.ID, Email: u.Email, Name: u.Name, Status: userStatus(u), TwoFactor: u.TwoFactor}
	created := u.CreatedAt
	if created == "" {
		created = u.CreationDate
	}
	v.Created = s.panelTime(created)
	if u.LastActive != nil {
		v.LastActive = s.panelTime(*u.LastActive)
	}
	if v.Name == v.Email {
		v.Name = ""
	}
	for _, m := range u.Organizations {
		v.Organizations = append(v.Organizations, serverMembershipView{ID: m.ID, Name: m.Name, Role: string(vault.RoleOf(m.Type))})
	}
	return v
}

// panelTime shows a panel timestamp in the configured zone; text the panel
// wrote in an unknown form is passed on unchanged rather than dropped.
func (s *server) panelTime(raw string) string {
	if raw == "" {
		return ""
	}
	if t, ok := vwadmin.ParseTime(raw); ok {
		return formatTime(t, s.Config.Location)
	}
	return raw
}

// serverOrganization is an organization as the account list shows it: the
// panel has no organization list a program can read, and it lists confirmed
// memberships only. An organization without a confirmed member is not here.
type serverOrganization struct {
	ID      string
	Name    string
	Members []string
	Owners  []string
}

func organizationsOf(users []vwadmin.User) []serverOrganization {
	byID := map[string]*serverOrganization{}
	for _, u := range users {
		for _, m := range u.Organizations {
			o := byID[m.ID]
			if o == nil {
				o = &serverOrganization{ID: m.ID, Name: m.Name}
				byID[m.ID] = o
			}
			o.Members = append(o.Members, u.Email)
			if m.Type == bitwarden.MemberOwner {
				o.Owners = append(o.Owners, u.Email)
			}
		}
	}
	out := make([]serverOrganization, 0, len(byID))
	for _, o := range byID {
		sort.Strings(o.Members)
		sort.Strings(o.Owners)
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// requireServer refuses a narrowed client: whoever holds the admin panel sees
// every account, so a client limited to some collections has no place here.
func (c *call) requireServer(write bool) error {
	if !c.principal.Unrestricted() {
		return fmt.Errorf("%w: client %q is narrowed to some collections and cannot administer the server", vault.ErrReadOnly, c.principal.Name)
	}
	if write {
		return c.requireWrite()
	}
	return nil
}

// findUser resolves an account by email or id within the account list, which
// is also the only answer of the panel that carries the last activity.
func findUser(users []vwadmin.User, ref string) (vwadmin.User, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return vwadmin.User{}, fmt.Errorf("%w: user is required", vault.ErrInvalid)
	}
	for _, u := range users {
		if u.ID == ref || strings.EqualFold(u.Email, ref) {
			return u, nil
		}
	}
	return vwadmin.User{}, fmt.Errorf("%w: user %q", vault.ErrNotFound, ref)
}

func (s *server) user(ctx context.Context, ref string) (vwadmin.User, []vwadmin.User, error) {
	users, err := s.Admin.Users(ctx)
	if err != nil {
		return vwadmin.User{}, nil, err
	}
	u, err := findUser(users, ref)
	return u, users, err
}

func (s *server) registerServerRead(srv *mcp.Server) {
	type statusOutput struct {
		Account              string   `json:"account" jsonschema:"label of this instance"`
		Mode                 string   `json:"mode" jsonschema:"server: administers the Vaultwarden server itself"`
		Client               string   `json:"client" jsonschema:"who you are to this instance"`
		ClientReadOnly       bool     `json:"client_read_only,omitempty"`
		Server               string   `json:"server" jsonschema:"the server this instance administers"`
		ServerVersion        string   `json:"server_version,omitempty" jsonschema:"the server's name and release, and the Bitwarden API version it implements"`
		Users                int      `json:"users"`
		Organizations        int      `json:"organizations" jsonschema:"organizations with at least one confirmed member"`
		AllowWrite           bool     `json:"allow_write"`
		AllowPermanentDelete bool     `json:"allow_permanent_delete" jsonschema:"whether delete_user and delete_organization exist on this instance"`
		InviteDomains        []string `json:"invite_domains,omitempty"`
		Version              string   `json:"version"`
		UptimeSeconds        int      `json:"uptime_seconds"`
		Tools                []string `json:"tools"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "get_status",
		Description: "Report what this instance is: the server it administers, how many accounts and organizations " +
			"it has, and which capabilities are switched on. Call it first when unsure what is possible.",
	}, func(ctx context.Context, c *call, _ struct{}) (statusOutput, error) {
		if err := c.requireServer(false); err != nil {
			return statusOutput{}, err
		}
		users, err := s.Admin.Users(ctx)
		if err != nil {
			return statusOutput{}, err
		}
		cfg := s.Config
		out := statusOutput{
			Account: cfg.Account, Mode: string(cfg.Mode), Client: c.principal.Name, ClientReadOnly: c.principal.ReadOnly,
			Server: cfg.Vaultwarden.URL, Users: len(users), Organizations: len(organizationsOf(users)),
			AllowWrite: cfg.Caps.AllowWrite && !c.principal.ReadOnly, AllowPermanentDelete: cfg.Caps.AllowPermanentDelete,
			InviteDomains: cfg.Caps.InviteDomains, Version: s.Version,
			UptimeSeconds: int(s.Clock().Sub(s.StartedAt).Seconds()), Tools: s.registered,
		}
		// The version is a courtesy; a server that does not describe itself is
		// still administered.
		if v, err := s.Admin.Version(ctx); err == nil {
			out.ServerVersion = strings.TrimSpace(v.Name + " " + v.Release)
			if v.API != "" {
				out.ServerVersion += " (API " + v.API + ")"
			}
		}
		return out, nil
	})

	type listUsersInput struct {
		Query        string `json:"query,omitempty" jsonschema:"optional text the email or name contains"`
		Status       string `json:"status,omitempty" jsonschema:"optional: active, invited or disabled"`
		Organization string `json:"organization,omitempty" jsonschema:"optional organization name or id the account is a confirmed member of"`
	}
	type listUsersOutput struct {
		Users []userView `json:"users"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "list_users",
		Description: "List the accounts of the server with their status, two-step login, last activity and confirmed organizations.",
	}, func(ctx context.Context, c *call, in listUsersInput) (listUsersOutput, error) {
		if err := c.requireServer(false); err != nil {
			return listUsersOutput{}, err
		}
		switch in.Status {
		case "", "active", "invited", "disabled":
		default:
			return listUsersOutput{}, fmt.Errorf("%w: status %q: want active, invited or disabled", vault.ErrInvalid, in.Status)
		}
		users, err := s.Admin.Users(ctx)
		if err != nil {
			return listUsersOutput{}, err
		}
		query := strings.ToLower(strings.TrimSpace(in.Query))
		out := listUsersOutput{Users: []userView{}}
		for _, u := range users {
			if query != "" && !strings.Contains(strings.ToLower(u.Email), query) && !strings.Contains(strings.ToLower(u.Name), query) {
				continue
			}
			if in.Status != "" && userStatus(u) != in.Status {
				continue
			}
			if in.Organization != "" && !slices.ContainsFunc(u.Organizations, func(m vwadmin.Membership) bool {
				return matchesOrg(m.ID, m.Name, in.Organization)
			}) {
				continue
			}
			out.Users = append(out.Users, s.toUserView(u))
		}
		sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Email < out.Users[j].Email })
		return out, nil
	})

	type userInput struct {
		User string `json:"user" jsonschema:"the account: its email or id"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "get_user",
		Description: "Show one account of the server: status, two-step login, last activity and confirmed organizations with roles.",
	}, func(ctx context.Context, c *call, in userInput) (userView, error) {
		if err := c.requireServer(false); err != nil {
			return userView{}, err
		}
		u, _, err := s.user(ctx, in.User)
		if err != nil {
			return userView{}, err
		}
		return s.toUserView(u), nil
	})

	type serverOrgView struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members int      `json:"members" jsonschema:"confirmed members"`
		Owners  []string `json:"owners" jsonschema:"confirmed owners"`
	}
	type serverOrgsOutput struct {
		Organizations []serverOrgView `json:"organizations"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "list_organizations",
		Description: "List the organizations of the server with their confirmed member count and owners. The admin " +
			"panel reports confirmed memberships only, so an organization without a confirmed member is not listed.",
	}, func(ctx context.Context, c *call, _ struct{}) (serverOrgsOutput, error) {
		if err := c.requireServer(false); err != nil {
			return serverOrgsOutput{}, err
		}
		users, err := s.Admin.Users(ctx)
		if err != nil {
			return serverOrgsOutput{}, err
		}
		out := serverOrgsOutput{Organizations: []serverOrgView{}}
		for _, o := range organizationsOf(users) {
			out.Organizations = append(out.Organizations, serverOrgView{ID: o.ID, Name: o.Name, Members: len(o.Members), Owners: nonNil(o.Owners)})
		}
		return out, nil
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *server) registerServerWrite(srv *mcp.Server) {
	type inviteInput struct {
		Email string `json:"email"`
	}
	type userOutput struct {
		User   userView `json:"user"`
		Status string   `json:"status"`
		Note   string   `json:"note,omitempty"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "invite_user",
		Description: "Create an invited account for an email address, so the person can register with it even where " +
			"open sign-ups are off. It gives access to no organization; that is an organization admin's invitation.",
	}, func(ctx context.Context, c *call, in inviteInput) (userOutput, error) {
		if err := c.requireServer(true); err != nil {
			return userOutput{}, err
		}
		email := strings.TrimSpace(in.Email)
		if !strings.Contains(email, "@") {
			return userOutput{}, fmt.Errorf("%w: %q is not an email address", vault.ErrInvalid, email)
		}
		if err := s.checkInviteDomain(email); err != nil {
			return userOutput{}, err
		}
		if err := s.Admin.Invite(ctx, email); err != nil {
			return userOutput{}, err
		}
		c.mutated("invite_user")
		c.note(slog.String("user", email))
		out := userOutput{User: userView{Email: email, Status: "invited"}, Status: "invited", Note: "the person registers with this address in the web vault"}
		// The invitation stands; reading the account back only fills in its id.
		if u, _, err := s.user(ctx, email); err == nil {
			out.User = s.toUserView(u)
		}
		return out, nil
	})

	type changeInput struct {
		User   string `json:"user" jsonschema:"the account: its email or id"`
		Action string `json:"action" jsonschema:"disable (blocks login and syncing, keeps everything), enable (lifts it), deauthorize (ends every session and device login) or resend_invite (mails the invitation again; a server without mail sends nothing)"`
	}
	actions := map[string]vwadmin.UserAction{
		"disable": vwadmin.ActionDisable, "enable": vwadmin.ActionEnable,
		"deauthorize": vwadmin.ActionDeauthorize, "resend_invite": vwadmin.ActionResendInvite,
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "change_user",
		Description: "Disable or enable an account, end all of its sessions, or resend its invitation. Nothing is deleted.",
	}, func(ctx context.Context, c *call, in changeInput) (userOutput, error) {
		if err := c.requireServer(true); err != nil {
			return userOutput{}, err
		}
		action, ok := actions[in.Action]
		if !ok {
			return userOutput{}, fmt.Errorf("%w: action %q: want disable, enable, deauthorize or resend_invite", vault.ErrInvalid, in.Action)
		}
		u, _, err := s.user(ctx, in.User)
		if err != nil {
			return userOutput{}, err
		}
		if action == vwadmin.ActionResendInvite && u.Status != vwadmin.StatusInvited {
			return userOutput{}, fmt.Errorf("%w: %s has already registered; there is no invitation to resend", vault.ErrInvalid, u.Email)
		}
		if err := s.Admin.ChangeUser(ctx, u.ID, action); err != nil {
			return userOutput{}, err
		}
		c.mutated(in.Action + "_user")
		c.note(slog.String("user", u.Email))
		// The change is made; reading the account back only refreshes the view.
		if after, _, err := s.user(ctx, u.ID); err == nil {
			u = after
		}
		return userOutput{User: s.toUserView(u), Status: in.Action}, nil
	})
}

// registerServerDelete adds the tools that destroy accounts and
// organizations; they exist only where permanent deletion is enabled. Each
// acts in two calls: the first shows the target and returns a code, the second
// must bring that code back. The code is issued by this instance and never
// derivable from the target, so an agent cannot skip the look.
func (s *server) registerServerDelete(srv *mcp.Server) {
	type deleteUserInput struct {
		User    string `json:"user" jsonschema:"the account: its email or id"`
		Confirm string `json:"confirm,omitempty" jsonschema:"the code the first call returned; omit it to see what would be deleted"`
	}
	type deleteUserOutput struct {
		User    userView `json:"user"`
		Deleted bool     `json:"deleted"`
		Confirm string   `json:"confirm,omitempty" jsonschema:"pass this back as confirm to delete; valid for five minutes, once"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "delete_user",
		Description: "Delete an account with its personal vault, in two calls: the first shows the account and returns " +
			"a confirmation code, the second deletes it when given that code. The last confirmed owner or member of " +
			"an organization is refused.",
	}, func(ctx context.Context, c *call, in deleteUserInput) (deleteUserOutput, error) {
		if err := c.requireServer(true); err != nil {
			return deleteUserOutput{}, err
		}
		u, users, err := s.user(ctx, in.User)
		if err != nil {
			return deleteUserOutput{}, err
		}
		for _, o := range organizationsOf(users) {
			if slices.Equal(o.Owners, []string{u.Email}) {
				return deleteUserOutput{}, fmt.Errorf("%w: %s is the only confirmed owner of %q; hand the organization over or delete it first", vault.ErrInvalid, u.Email, o.Name)
			}
			// The organization would lose its last confirmed member and with it
			// the only way this instance can see or delete it.
			if slices.Equal(o.Members, []string{u.Email}) {
				return deleteUserOutput{}, fmt.Errorf("%w: %s is the only confirmed member of %q; delete the organization first", vault.ErrInvalid, u.Email, o.Name)
			}
		}
		out := deleteUserOutput{User: s.toUserView(u)}
		if strings.TrimSpace(in.Confirm) == "" {
			if out.Confirm, err = s.confirms.issue("delete_user", u.ID, c.principal.Name); err != nil {
				return deleteUserOutput{}, err
			}
			return out, nil
		}
		if !s.confirms.take(in.Confirm, "delete_user", u.ID, c.principal.Name) {
			return deleteUserOutput{}, fmt.Errorf("%w: the confirmation code is not valid for this account; call delete_user without confirm for a new one", vault.ErrInvalid)
		}
		if err := s.Admin.ChangeUser(ctx, u.ID, vwadmin.ActionDelete); err != nil {
			return deleteUserOutput{}, err
		}
		c.mutated("delete_user")
		c.note(slog.String("user", u.Email))
		out.Deleted = true
		return out, nil
	})

	type deleteOrgInput struct {
		Organization string `json:"organization" jsonschema:"organization name or id; an organization without confirmed members is reached by id only"`
		Confirm      string `json:"confirm,omitempty" jsonschema:"the code the first call returned; omit it to see what would be deleted"`
	}
	type deleteOrgOutput struct {
		ID      string   `json:"id"`
		Name    string   `json:"name,omitempty"`
		Members []string `json:"members" jsonschema:"confirmed members"`
		Deleted bool     `json:"deleted"`
		Note    string   `json:"note,omitempty"`
		Confirm string   `json:"confirm,omitempty" jsonschema:"pass this back as confirm to delete; valid for five minutes, once"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "delete_organization",
		Description: "Delete an organization with every collection and item in it, in two calls: the first shows the " +
			"organization and its confirmed members and returns a confirmation code, the second deletes it when given that code.",
	}, func(ctx context.Context, c *call, in deleteOrgInput) (deleteOrgOutput, error) {
		if err := c.requireServer(true); err != nil {
			return deleteOrgOutput{}, err
		}
		ref := strings.TrimSpace(in.Organization)
		if ref == "" {
			return deleteOrgOutput{}, fmt.Errorf("%w: organization is required", vault.ErrInvalid)
		}
		users, err := s.Admin.Users(ctx)
		if err != nil {
			return deleteOrgOutput{}, err
		}
		var out deleteOrgOutput
		var matches []serverOrganization
		for _, o := range organizationsOf(users) {
			if o.ID == ref {
				matches = []serverOrganization{o}
				break
			}
			if strings.EqualFold(o.Name, ref) {
				matches = append(matches, o)
			}
		}
		switch {
		case len(matches) == 1:
			o := matches[0]
			out = deleteOrgOutput{ID: o.ID, Name: o.Name, Members: o.Members}
		case len(matches) > 1:
			return deleteOrgOutput{}, fmt.Errorf("%w: organization %q matches %d organizations; pass the id", vault.ErrAmbiguous, ref, len(matches))
		case isUUID(ref):
			out = deleteOrgOutput{ID: strings.ToLower(ref), Members: []string{}, Note: "no confirmed member, so the panel does not describe it; it is deleted by id"}
		default:
			return deleteOrgOutput{}, fmt.Errorf("%w: organization %q; one without confirmed members is reached by id only", vault.ErrNotFound, ref)
		}
		if strings.TrimSpace(in.Confirm) == "" {
			if out.Confirm, err = s.confirms.issue("delete_organization", out.ID, c.principal.Name); err != nil {
				return deleteOrgOutput{}, err
			}
			return out, nil
		}
		if !s.confirms.take(in.Confirm, "delete_organization", out.ID, c.principal.Name) {
			return deleteOrgOutput{}, fmt.Errorf("%w: the confirmation code is not valid for this organization; call delete_organization without confirm for a new one", vault.ErrInvalid)
		}
		if err := s.Admin.DeleteOrganization(ctx, out.ID); err != nil {
			return deleteOrgOutput{}, err
		}
		c.mutated("delete_organization")
		c.note(slog.String("organization", out.Name), slog.String("organization_id", out.ID))
		out.Deleted = true
		return out, nil
	})
}

var uuidShape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidShape.MatchString(s) }

// confirmTTL is how long a confirmation code of a deletion stays valid.
const confirmTTL = 5 * time.Minute

// confirmBook holds the codes the first call of a deletion issues. A code is
// bound to the tool, the target and the client, and is taken once.
type confirmBook struct {
	mu      sync.Mutex
	now     func() time.Time
	pending map[string]pendingConfirm
}

type pendingConfirm struct {
	tool, target, client string
	expires              time.Time
}

func newConfirmBook(now func() time.Time) *confirmBook {
	return &confirmBook{now: now, pending: map[string]pendingConfirm{}}
}

func (b *confirmBook) issue(tool, target, client string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := hex.EncodeToString(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for k, p := range b.pending {
		if !now.Before(p.expires) {
			delete(b.pending, k)
		}
	}
	b.pending[code] = pendingConfirm{tool: tool, target: target, client: client, expires: now.Add(confirmTTL)}
	return code, nil
}

func (b *confirmBook) take(code, tool, target, client string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[strings.TrimSpace(code)]
	if !ok || p.tool != tool || p.target != target || p.client != client || !b.now().Before(p.expires) {
		return false
	}
	delete(b.pending, strings.TrimSpace(code))
	return true
}
