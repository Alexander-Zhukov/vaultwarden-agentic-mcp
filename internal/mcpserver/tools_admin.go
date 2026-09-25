package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

type grantInput struct {
	Collection    string `json:"collection" jsonschema:"collection name or id"`
	ReadOnly      bool   `json:"read_only,omitempty"`
	HidePasswords bool   `json:"hide_passwords,omitempty" jsonschema:"the member sees items but official clients hide their secret values"`
	Manage        bool   `json:"manage,omitempty" jsonschema:"the member may manage the collection's access"`
}

type memberGrantInput struct {
	Member        string `json:"member" jsonschema:"member email or membership id"`
	ReadOnly      bool   `json:"read_only,omitempty"`
	HidePasswords bool   `json:"hide_passwords,omitempty"`
	Manage        bool   `json:"manage,omitempty"`
}

type accessView struct {
	Collection    string `json:"collection"`
	ReadOnly      bool   `json:"read_only,omitempty"`
	HidePasswords bool   `json:"hide_passwords,omitempty"`
	Manage        bool   `json:"manage,omitempty"`
}

type memberView struct {
	ID          string       `json:"id" jsonschema:"membership id"`
	Email       string       `json:"email"`
	Name        string       `json:"name,omitempty"`
	Status      string       `json:"status" jsonschema:"invited, accepted (waits for confirm_member), confirmed or revoked"`
	Role        string       `json:"role" jsonschema:"owner, admin, manager or user"`
	AccessAll   bool         `json:"access_all,omitempty"`
	Collections []accessView `json:"collections,omitempty"`
}

func toGrants(in []grantInput) []vault.Grant {
	out := make([]vault.Grant, len(in))
	for i, g := range in {
		out[i] = vault.Grant{Collection: g.Collection, ReadOnly: g.ReadOnly, HidePasswords: g.HidePasswords, Manage: g.Manage}
	}
	return out
}

func toMemberAccess(in []memberGrantInput) []vault.MemberAccess {
	if in == nil {
		return nil
	}
	out := make([]vault.MemberAccess, len(in))
	for i, g := range in {
		out[i] = vault.MemberAccess{Member: g.Member, ReadOnly: g.ReadOnly, HidePasswords: g.HidePasswords, Manage: g.Manage}
	}
	return out
}

// admin returns the management view of one organization for an unrestricted,
// writable client. Organization management is all-or-nothing: a client
// narrowed to some collections must not change who sees the others.
func (c *call) admin(ctx context.Context, write bool, org string) (*vault.Admin, error) {
	if !c.principal.Unrestricted() {
		return nil, fmt.Errorf("%w: client %q is narrowed to some collections and cannot manage the organization", vault.ErrReadOnly, c.principal.Name)
	}
	if write {
		if err := c.requireWrite(); err != nil {
			return nil, err
		}
	}
	admin, err := c.server.Vault.Admin(ctx, org, c.server.Config.Organizations)
	if err != nil {
		return nil, err
	}
	// With several organizations managed, the audit record must say which one
	// a change touched.
	c.note(slog.String("organization", admin.OrganizationName()))
	return admin, nil
}

func (s *server) registerAdminRead(srv *mcp.Server) {
	type orgInput struct {
		Organization string `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
	}
	type orgView struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Role        string `json:"role" jsonschema:"the account's role: owner, admin, manager or user"`
		Managed     bool   `json:"managed" jsonschema:"whether the admin tools of this instance act on it"`
		Members     int    `json:"members,omitempty"`
		Collections int    `json:"collections,omitempty"`
	}
	type orgsOutput struct {
		Organizations []orgView `json:"organizations"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "list_organizations",
		Description: "List the organizations of the account with its role in each, and which ones this instance " +
			"manages; managed ones also show their member and collection counts. Admin tools take one of these as organization.",
	}, func(ctx context.Context, c *call, _ struct{}) (orgsOutput, error) {
		if !c.principal.Unrestricted() {
			return orgsOutput{}, fmt.Errorf("%w: client %q is narrowed to some collections and cannot manage organizations", vault.ErrReadOnly, c.principal.Name)
		}
		orgs, err := s.Vault.Organizations(ctx, s.Config.Organizations)
		if err != nil {
			return orgsOutput{}, err
		}
		out := orgsOutput{Organizations: []orgView{}}
		for _, o := range orgs {
			v := orgView{ID: o.ID, Name: o.Name, Role: string(o.Role), Managed: o.Managed}
			if o.Managed {
				admin, err := s.Vault.Admin(ctx, o.ID, s.Config.Organizations)
				if err != nil {
					return orgsOutput{}, err
				}
				members, err := admin.Members(ctx)
				if err != nil {
					return orgsOutput{}, err
				}
				cols, err := admin.Collections(ctx)
				if err != nil {
					return orgsOutput{}, err
				}
				v.Members, v.Collections = len(members), len(cols)
			}
			out.Organizations = append(out.Organizations, v)
		}
		return out, nil
	})

	type membersOutput struct {
		Organization string       `json:"organization"`
		Members      []memberView `json:"members"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "list_members",
		Description: "List the organization's members with their status, role and collection access.",
	}, func(ctx context.Context, c *call, in orgInput) (membersOutput, error) {
		admin, err := c.admin(ctx, false, in.Organization)
		if err != nil {
			return membersOutput{}, err
		}
		members, err := admin.Members(ctx)
		if err != nil {
			return membersOutput{}, err
		}
		out := membersOutput{Organization: admin.OrganizationName(), Members: []memberView{}}
		for _, m := range members {
			v := memberView{ID: m.ID, Email: m.Email, Name: m.Name, Status: m.Status, Role: string(m.Role), AccessAll: m.AccessAll}
			for _, a := range m.Collections {
				v.Collections = append(v.Collections, accessView{Collection: a.Collection, ReadOnly: a.ReadOnly, HidePasswords: a.HidePasswords, Manage: a.Manage})
			}
			out.Members = append(out.Members, v)
		}
		return out, nil
	})

	type eventsInput struct {
		Organization string `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Since        string `json:"since,omitempty" jsonschema:"how far back, e.g. 1h or 72h; default 24h"`
		Limit        int    `json:"limit,omitempty" jsonschema:"at most this many events, default 100, at most 1000"`
	}
	type eventView struct {
		Time       string `json:"time"`
		Type       string `json:"type"`
		Actor      string `json:"actor,omitempty"`
		Member     string `json:"member,omitempty"`
		Item       string `json:"item,omitempty"`
		ItemID     string `json:"item_id,omitempty"`
		Collection string `json:"collection,omitempty"`
		IP         string `json:"ip,omitempty"`
	}
	type eventsOutput struct {
		Events []eventView `json:"events"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "list_events",
		Description: "Read the organization's event log, newest first: logins, item changes and views, " +
			"membership and collection changes. Empty when the server does not record organization events.",
	}, func(ctx context.Context, c *call, in eventsInput) (eventsOutput, error) {
		admin, err := c.admin(ctx, false, in.Organization)
		if err != nil {
			return eventsOutput{}, err
		}
		since := 24 * time.Hour
		if in.Since != "" {
			if since, err = time.ParseDuration(in.Since); err != nil || since <= 0 {
				return eventsOutput{}, fmt.Errorf("%w: since %q is not a positive duration", vault.ErrInvalid, in.Since)
			}
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 100
		}
		limit = min(limit, 1000)
		now := s.Clock()
		events, err := admin.Events(ctx, now.Add(-since), now, limit)
		if err != nil {
			return eventsOutput{}, err
		}
		out := eventsOutput{Events: []eventView{}}
		for _, e := range events {
			out.Events = append(out.Events, eventView{
				Time: formatTime(e.Time, s.Config.Location), Type: e.Type, Actor: e.Actor, Member: e.Member,
				Item: e.Item, ItemID: e.ItemID, Collection: e.Collection, IP: e.IP,
			})
		}
		return out, nil
	})
}

// registerAdminWrite adds the organization tools that change it; they exist
// only where writing is enabled.
func (s *server) registerAdminWrite(srv *mcp.Server) {
	type okOutput struct {
		Member string `json:"member"`
		Status string `json:"status"`
		Note   string `json:"note,omitempty"`
	}
	type inviteInput struct {
		Organization string       `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Email        string       `json:"email"`
		Role         string       `json:"role,omitempty" jsonschema:"user (default), manager, admin or owner"`
		Collections  []grantInput `json:"collections,omitempty" jsonschema:"collections the member gets and how"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "invite_member",
		Description: "Invite an account to the organization with a role and collection access. The member then " +
			"accepts the invitation, and confirm_member completes it.",
	}, func(ctx context.Context, c *call, in inviteInput) (okOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return okOutput{}, err
		}
		role := vault.RoleUser
		if in.Role != "" {
			if role, err = vault.ParseRole(in.Role); err != nil {
				return okOutput{}, err
			}
		}
		if err := s.checkRole(role); err != nil {
			return okOutput{}, err
		}
		if err := s.checkInviteDomain(in.Email); err != nil {
			return okOutput{}, err
		}
		if err := admin.Invite(ctx, in.Email, role, toGrants(in.Collections)); err != nil {
			return okOutput{}, err
		}
		c.mutated("invite_member")
		c.note(slog.String("member", in.Email), slog.String("role", string(role)))
		return okOutput{Member: in.Email, Status: "invited", Note: "confirm_member once the invitation is accepted"}, nil
	})

	type confirmInput struct {
		Organization      string `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Member            string `json:"member" jsonschema:"member email or membership id"`
		FingerprintPhrase string `json:"fingerprint_phrase,omitempty" jsonschema:"the member's fingerprint phrase as their own client shows it (Settings → My account); omit it to get the phrase without confirming"`
	}
	type confirmOutput struct {
		Member            string `json:"member"`
		Status            string `json:"status" jsonschema:"accepted (not yet confirmed) or confirmed"`
		FingerprintPhrase string `json:"fingerprint_phrase" jsonschema:"the phrase of the key the server hands out for this member"`
		Next              string `json:"next,omitempty"`
	}
	addTool(s, srv, &mcp.Tool{
		Name: "confirm_member",
		Description: "Complete an accepted invitation in two steps. Without fingerprint_phrase it only returns the " +
			"phrase of the member's key: have the member (or their operator) compare it with the phrase their own " +
			"client shows. Call again with the phrase they confirmed; only then is the organization key encrypted " +
			"for that key. A mismatch means the server is handing out a key that is not the member's.",
	}, func(ctx context.Context, c *call, in confirmInput) (confirmOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return confirmOutput{}, err
		}
		m, phrase, err := admin.Confirm(ctx, in.Member, in.FingerprintPhrase)
		if err != nil {
			return confirmOutput{}, err
		}
		out := confirmOutput{Member: m.Email, Status: m.Status, FingerprintPhrase: phrase}
		if in.FingerprintPhrase == "" {
			out.Next = "compare this phrase with the one the member's client shows, then call confirm_member again with it"
			return out, nil
		}
		c.mutated("confirm_member")
		c.note(slog.String("member", m.Email))
		return out, nil
	})

	type updateMemberInput struct {
		Organization string       `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Member       string       `json:"member" jsonschema:"member email or membership id"`
		Role         string       `json:"role,omitempty" jsonschema:"new role: user, manager, admin or owner; unchanged when empty"`
		Collections  []grantInput `json:"collections,omitempty" jsonschema:"replaces the member's collection access; unchanged when omitted"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "update_member",
		Description: "Change a member's role or collection access. Collections replace the current access entirely.",
	}, func(ctx context.Context, c *call, in updateMemberInput) (okOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return okOutput{}, err
		}
		var role *vault.Role
		if in.Role != "" {
			r, err := vault.ParseRole(in.Role)
			if err != nil {
				return okOutput{}, err
			}
			if err := s.checkRole(r); err != nil {
				return okOutput{}, err
			}
			role = &r
		}
		var grants []vault.Grant
		if in.Collections != nil {
			grants = toGrants(in.Collections)
		}
		if role == nil && grants == nil {
			return okOutput{}, fmt.Errorf("%w: nothing to change", vault.ErrInvalid)
		}
		if err := s.checkMember(ctx, admin, in.Member); err != nil {
			return okOutput{}, err
		}
		if err := admin.UpdateMember(ctx, in.Member, role, grants); err != nil {
			return okOutput{}, err
		}
		c.mutated("update_member")
		c.note(slog.String("member", in.Member))
		return okOutput{Member: in.Member, Status: "updated"}, nil
	})

	type changeMemberInput struct {
		Organization string `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Member       string `json:"member" jsonschema:"member email or membership id"`
		Action       string `json:"action" jsonschema:"revoke (suspend, keeps the membership), restore (lift a revocation) or remove (delete the membership)"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "change_member",
		Description: "Revoke, restore or remove a membership. This instance's own membership cannot be changed.",
	}, func(ctx context.Context, c *call, in changeMemberInput) (okOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return okOutput{}, err
		}
		if err := s.checkMember(ctx, admin, in.Member); err != nil {
			return okOutput{}, err
		}
		m, err := admin.ChangeMember(ctx, in.Member, vault.MemberAction(in.Action))
		if err != nil {
			return okOutput{}, err
		}
		c.mutated(in.Action + "_member")
		c.note(slog.String("member", m.Email))
		return okOutput{Member: m.Email, Status: in.Action + "d"}, nil
	})

	type createCollectionInput struct {
		Organization string             `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Name         string             `json:"name"`
		Members      []memberGrantInput `json:"members,omitempty" jsonschema:"who gets access and how"`
	}
	type collectionOutput struct {
		ID      string             `json:"id"`
		Name    string             `json:"name"`
		Members []memberAccessView `json:"members,omitempty"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "create_collection",
		Description: "Create a collection in the organization and grant members access to it.",
	}, func(ctx context.Context, c *call, in createCollectionInput) (collectionOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return collectionOutput{}, err
		}
		col, err := admin.CreateCollection(ctx, in.Name, toMemberAccess(in.Members))
		if err != nil {
			return collectionOutput{}, err
		}
		c.mutated("create_collection")
		c.note(slog.String("collection", col.Name))
		return collectionOutput{ID: col.ID, Name: col.Name}, nil
	})

	type updateCollectionInput struct {
		Organization string             `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Collection   string             `json:"collection" jsonschema:"collection name or id"`
		Name         string             `json:"name,omitempty" jsonschema:"new name; unchanged when empty"`
		Members      []memberGrantInput `json:"members,omitempty" jsonschema:"replaces who has access; unchanged when omitted"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "update_collection",
		Description: "Rename a collection or replace who has access to it.",
	}, func(ctx context.Context, c *call, in updateCollectionInput) (collectionOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return collectionOutput{}, err
		}
		col, err := admin.UpdateCollection(ctx, in.Collection, in.Name, toMemberAccess(in.Members))
		if err != nil {
			return collectionOutput{}, err
		}
		c.mutated("update_collection")
		c.note(slog.String("collection", col.Name))
		out := collectionOutput{ID: col.ID, Name: col.Name}
		for _, m := range col.Members {
			out.Members = append(out.Members, memberAccessView{Member: m.Member, ReadOnly: m.ReadOnly, HidePasswords: m.HidePasswords, Manage: m.Manage})
		}
		return out, nil
	})

	type deleteCollectionInput struct {
		Organization string `json:"organization,omitempty" jsonschema:"organization name or id; required when this instance manages several (see list_organizations)"`
		Collection   string `json:"collection" jsonschema:"collection name or id"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "delete_collection",
		Description: "Delete an empty collection. A collection that still holds items is refused; move them with set_item_collections first.",
	}, func(ctx context.Context, c *call, in deleteCollectionInput) (collectionOutput, error) {
		admin, err := c.admin(ctx, true, in.Organization)
		if err != nil {
			return collectionOutput{}, err
		}
		col, err := admin.DeleteCollection(ctx, in.Collection)
		if err != nil {
			return collectionOutput{}, err
		}
		c.mutated("delete_collection")
		c.note(slog.String("collection", col.Name))
		return collectionOutput{ID: col.ID, Name: col.Name}, nil
	})

	type setCollectionsInput struct {
		Item        string   `json:"item" jsonschema:"the item: its id, or its name"`
		Collection  string   `json:"collection,omitempty" jsonschema:"optional current collection, to disambiguate a name"`
		Collections []string `json:"collections" jsonschema:"the complete new set of collections, names or ids"`
	}
	addTool(s, srv, &mcp.Tool{
		Name:        "set_item_collections",
		Description: "Move an item between collections, or put it in several: the list replaces its collections.",
	}, func(ctx context.Context, c *call, in setCollectionsInput) (writeOutput, error) {
		_, it, err := c.item(ctx, in.Item, in.Collection, false)
		if err != nil {
			return writeOutput{}, err
		}
		if it.OrganizationID == "" {
			return writeOutput{}, fmt.Errorf("%w: %q is in the account's personal vault, not in an organization", vault.ErrInvalid, it.Name)
		}
		// The item's organization is the one being managed.
		if _, err := c.admin(ctx, true, it.OrganizationID); err != nil {
			return writeOutput{}, err
		}
		moved, err := s.Vault.SetCollections(ctx, vault.ItemRef{Ref: it.ID}, in.Collections)
		if err != nil {
			return writeOutput{}, err
		}
		// Links issued while the item lived elsewhere were issued under a
		// different reach.
		s.Links.Revoke(it.ID)
		c.mutated("set_item_collections")
		snap, err := c.snapshot(ctx)
		if err != nil {
			return writeOutput{}, err
		}
		return writeOutput{Item: summarize(snap, &moved, s.Config)}, nil
	})
}

// checkRole refuses the owner and admin roles unless the deployment allows
// granting them: a prompt-injected agent that can mint an owner has taken the
// organization.
func (s *server) checkRole(r vault.Role) error {
	if (r == vault.RoleOwner || r == vault.RoleAdmin) && !s.Config.Caps.AllowAdminRoles {
		return fmt.Errorf("%w: the %s role is not handled here (VWMCP_ALLOW_ADMIN_ROLES)", errDisabled, r)
	}
	return nil
}

// checkMember refuses to change an owner or admin — demote, revoke, restore or
// remove — unless the deployment allows handling those roles.
func (s *server) checkMember(ctx context.Context, admin *vault.Admin, member string) error {
	current, err := admin.MemberRole(ctx, member)
	if err != nil {
		return err
	}
	return s.checkRole(current)
}

// checkInviteDomain refuses an address outside the configured domains.
func (s *server) checkInviteDomain(email string) error {
	domains := s.Config.Caps.InviteDomains
	if len(domains) == 0 {
		return nil
	}
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	if ok && slices.ContainsFunc(domains, func(d string) bool { return strings.EqualFold(d, domain) }) {
		return nil
	}
	return fmt.Errorf("%w: %q is outside the domains this instance may invite (VWMCP_INVITE_DOMAINS)", errDisabled, email)
}
