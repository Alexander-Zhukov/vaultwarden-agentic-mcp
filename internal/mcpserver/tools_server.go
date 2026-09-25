package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwadmin"
)

type serverMembershipView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role" jsonschema:"owner, admin, manager or user"`
	Status string `json:"status" jsonschema:"invited, accepted, confirmed or revoked"`
}

type userView struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Name          string                 `json:"name,omitempty"`
	Status        string                 `json:"status" jsonschema:"active, invited (has not registered yet) or disabled"`
	TwoFactor     bool                   `json:"two_factor"`
	Created       string                 `json:"created,omitempty"`
	LastActive    string                 `json:"last_active,omitempty"`
	Organizations []serverMembershipView `json:"organizations,omitempty"`
}

func userStatus(u vwadmin.User) string {
	switch {
	case u.Status == vwadmin.StatusInvited:
		return "invited"
	case u.Status == vwadmin.StatusDisabled, u.Enabled != nil && !*u.Enabled:
		return "disabled"
	default:
		return "active"
	}
}

func memberRole(t int) string {
	switch bitwarden.MemberType(t) {
	case bitwarden.MemberOwner:
		return "owner"
	case bitwarden.MemberAdmin:
		return "admin"
	case bitwarden.MemberManager, bitwarden.MemberCustom:
		return "manager"
	case bitwarden.MemberUser:
		return "user"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

func membershipStatus(s int) string {
	switch bitwarden.MemberStatus(s) {
	case bitwarden.MemberRevoked:
		return "revoked"
	case bitwarden.MemberInvited:
		return "invited"
	case bitwarden.MemberAccepted:
		return "accepted"
	case bitwarden.MemberConfirmed:
		return "confirmed"
	default:
		return fmt.Sprintf("status_%d", s)
	}
}

func toUserView(u vwadmin.User) userView {
	v := userView{ID: u.ID, Email: u.Email, Name: u.Name, Status: userStatus(u), TwoFactor: u.TwoFactor, Created: u.CreatedAt}
	if v.Created == "" {
		v.Created = u.CreationDate
	}
	if u.LastActive != nil {
		v.LastActive = *u.LastActive
	}
	if v.Name == v.Email {
		v.Name = ""
	}
	for _, m := range u.Organizations {
		v.Organizations = append(v.Organizations, serverMembershipView{ID: m.ID, Name: m.Name, Role: memberRole(m.Type), Status: membershipStatus(m.Status)})
	}
	return v
}

// serverOrganization is an organization as the account list shows it: the
// panel has no organization list of its own that a program can read.
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
			if bitwarden.MemberType(m.Type) == bitwarden.MemberOwner && bitwarden.MemberStatus(m.Status) == bitwarden.MemberConfirmed {
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

// findUser resolves an account by email or id.
func (s *server) findUser(ctx context.Context, ref string) (vwadmin.User, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return vwadmin.User{}, fmt.Errorf("%w: user is required", vault.ErrInvalid)
	}
	var (
		u   vwadmin.User
		err error
	)
	if strings.Contains(ref, "@") {
		u, err = s.Admin.UserByEmail(ctx, ref)
	} else {
		u, err = s.Admin.User(ctx, ref)
	}
	if errors.Is(err, vwadmin.ErrNotFound) {
		return vwadmin.User{}, fmt.Errorf("%w: user %q", vault.ErrNotFound, ref)
	}
	return u, err
}

func (s *server) registerServerRead(srv *mcp.Server) {
	type statusOutput struct {
		Account              string   `json:"account" jsonschema:"label of this instance"`
		Mode                 string   `json:"mode" jsonschema:"server: administers the Vaultwarden server itself"`
		Client               string   `json:"client" jsonschema:"who you are to this instance"`
		ClientReadOnly       bool     `json:"client_read_only,omitempty"`
		Server               string   `json:"server" jsonschema:"the server this instance administers"`
		ServerVersion        string   `json:"server_version,omitempty" jsonschema:"the server's name and the Bitwarden API version it implements"`
		Users                int      `json:"users"`
		Organizations        int      `json:"organizations"`
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
		if v, err := s.Admin.Version(ctx); err == nil {
			out.ServerVersion = strings.TrimSpace(v.Server.Name + ", API " + v.API)
		}
		return out, nil
	})

	type listUsersInput struct {
		Query        string `json:"query,omitempty" jsonschema:"optional text the email or name contains"`
		Status       string `json:"status,omitempty" jsonschema:"optional: active, invited or disabled"`
		Organization string `json:"organization,omitempty" jsonschema:"optional organization name or id the account belongs to"`
	}
	type listUsersOutput struct {
		Users []userView `json:"users"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "list_users",
		Description: "List the accounts of the server with their status, two-step login, last activity and organizations.",
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
			v := toUserView(u)
			if query != "" && !strings.Contains(strings.ToLower(u.Email), query) && !strings.Contains(strings.ToLower(u.Name), query) {
				continue
			}
			if in.Status != "" && v.Status != in.Status {
				continue
			}
			if in.Organization != "" && !slices.ContainsFunc(u.Organizations, func(m vwadmin.Membership) bool {
				return matchesOrg(m.ID, m.Name, in.Organization)
			}) {
				continue
			}
			out.Users = append(out.Users, v)
		}
		sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Email < out.Users[j].Email })
		return out, nil
	})

	type userInput struct {
		User string `json:"user" jsonschema:"the account: its email or id"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "get_user",
		Description: "Show one account of the server: status, two-step login, last activity and organizations with roles.",
	}, func(ctx context.Context, c *call, in userInput) (userView, error) {
		if err := c.requireServer(false); err != nil {
			return userView{}, err
		}
		u, err := s.findUser(ctx, in.User)
		if err != nil {
			return userView{}, err
		}
		return toUserView(u), nil
	})

	type serverOrgView struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members int      `json:"members"`
		Owners  []string `json:"owners" jsonschema:"confirmed owners"`
	}
	type serverOrgsOutput struct {
		Organizations []serverOrgView `json:"organizations"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "list_organizations",
		Description: "List every organization of the server with its member count and confirmed owners.",
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
		u, err := s.Admin.Invite(ctx, email)
		if err != nil {
			return userOutput{}, err
		}
		c.mutated("invite_user")
		c.note(slog.String("user", email))
		return userOutput{User: toUserView(u), Status: "invited", Note: "the person registers with this address in the web vault"}, nil
	})

	type changeInput struct {
		User   string `json:"user" jsonschema:"the account: its email or id"`
		Action string `json:"action" jsonschema:"disable (blocks login and syncing, keeps everything), enable (lifts it), deauthorize (ends every session and device login) or resend_invite (mails the invitation again)"`
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
		u, err := s.findUser(ctx, in.User)
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
		if after, err := s.Admin.User(ctx, u.ID); err == nil {
			u = after
		}
		return userOutput{User: toUserView(u), Status: in.Action}, nil
	})
}

// registerServerDelete adds the tools that destroy accounts and
// organizations; they exist only where permanent deletion is enabled.
func (s *server) registerServerDelete(srv *mcp.Server) {
	type deleteUserInput struct {
		User    string `json:"user" jsonschema:"the account: its email or id"`
		Confirm string `json:"confirm,omitempty" jsonschema:"the account's email, exactly; omit it to see what would be deleted"`
	}
	type deleteUserOutput struct {
		User    userView `json:"user"`
		Deleted bool     `json:"deleted"`
		Next    string   `json:"next,omitempty"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "delete_user",
		Description: "Delete an account with its personal vault, in two steps: without confirm it shows the account; " +
			"with confirm set to its email it deletes it. The only owner of an organization is refused.",
	}, func(ctx context.Context, c *call, in deleteUserInput) (deleteUserOutput, error) {
		if err := c.requireServer(true); err != nil {
			return deleteUserOutput{}, err
		}
		u, err := s.findUser(ctx, in.User)
		if err != nil {
			return deleteUserOutput{}, err
		}
		users, err := s.Admin.Users(ctx)
		if err != nil {
			return deleteUserOutput{}, err
		}
		for _, o := range organizationsOf(users) {
			if len(o.Owners) == 1 && o.Owners[0] == u.Email {
				return deleteUserOutput{}, fmt.Errorf("%w: %s is the only owner of %q; hand the organization over or delete it first", vault.ErrInvalid, u.Email, o.Name)
			}
		}
		out := deleteUserOutput{User: toUserView(u)}
		if strings.TrimSpace(in.Confirm) == "" {
			out.Next = "call delete_user again with confirm set to " + u.Email
			return out, nil
		}
		if !strings.EqualFold(strings.TrimSpace(in.Confirm), u.Email) {
			return deleteUserOutput{}, fmt.Errorf("%w: confirm does not match the account's email", vault.ErrInvalid)
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
		Organization string `json:"organization" jsonschema:"organization name or id"`
		Confirm      string `json:"confirm,omitempty" jsonschema:"the organization's name, exactly; omit it to see what would be deleted"`
	}
	type deleteOrgOutput struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members []string `json:"members"`
		Deleted bool     `json:"deleted"`
		Next    string   `json:"next,omitempty"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "delete_organization",
		Description: "Delete an organization with every collection and item in it, in two steps: without confirm it " +
			"shows the organization and its members; with confirm set to its exact name it deletes it.",
	}, func(ctx context.Context, c *call, in deleteOrgInput) (deleteOrgOutput, error) {
		if err := c.requireServer(true); err != nil {
			return deleteOrgOutput{}, err
		}
		users, err := s.Admin.Users(ctx)
		if err != nil {
			return deleteOrgOutput{}, err
		}
		var matches []serverOrganization
		for _, o := range organizationsOf(users) {
			if matchesOrg(o.ID, o.Name, in.Organization) {
				matches = append(matches, o)
			}
		}
		switch {
		case strings.TrimSpace(in.Organization) == "":
			return deleteOrgOutput{}, fmt.Errorf("%w: organization is required", vault.ErrInvalid)
		case len(matches) == 0:
			return deleteOrgOutput{}, fmt.Errorf("%w: organization %q", vault.ErrNotFound, in.Organization)
		case len(matches) > 1:
			return deleteOrgOutput{}, fmt.Errorf("%w: organization %q matches %d organizations; pass the id", vault.ErrAmbiguous, in.Organization, len(matches))
		}
		o := matches[0]
		out := deleteOrgOutput{ID: o.ID, Name: o.Name, Members: o.Members}
		if strings.TrimSpace(in.Confirm) == "" {
			out.Next = fmt.Sprintf("call delete_organization again with confirm set to %q", o.Name)
			return out, nil
		}
		if in.Confirm != o.Name {
			return deleteOrgOutput{}, fmt.Errorf("%w: confirm does not match the organization's name", vault.ErrInvalid)
		}
		if err := s.Admin.DeleteOrganization(ctx, o.ID); err != nil {
			return deleteOrgOutput{}, err
		}
		c.mutated("delete_organization")
		c.note(slog.String("organization", o.Name))
		out.Deleted = true
		return out, nil
	})
}
