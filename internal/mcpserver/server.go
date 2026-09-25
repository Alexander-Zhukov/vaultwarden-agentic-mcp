// Package mcpserver is the MCP surface of the service: the tools an agent
// calls, the one-time link endpoints, and the policy between them and the
// vault — who may see which collection, what may be written, and which values
// may ever reach the model.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/access"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/obs"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwadmin"
)

// Deps are everything the MCP layer needs.
type Deps struct {
	Config *config.Config
	// Vault serves the consumer and admin modes.
	Vault *vault.Vault
	// Admin serves the server mode.
	Admin   *vwadmin.Client
	Links   *links.Store
	Metrics *obs.Metrics
	Logger  *slog.Logger
	Clock   func() time.Time
	// Local is the principal of a caller without a token: the stdio client,
	// or anyone when authentication is disabled.
	Local access.Principal
	// StartedAt is what get_status reports uptime against.
	StartedAt time.Time
	Version   string
}

func (d Deps) validate() error {
	var missing []string
	if d.Config == nil || d.Config.Location == nil {
		missing = append(missing, "Config")
	}
	if d.Config != nil && d.Config.Mode == config.ModeServer {
		if d.Admin == nil {
			missing = append(missing, "Admin")
		}
	} else if d.Vault == nil {
		missing = append(missing, "Vault")
	}
	if d.Links == nil {
		missing = append(missing, "Links")
	}
	if d.Metrics == nil {
		missing = append(missing, "Metrics")
	}
	if d.Logger == nil {
		missing = append(missing, "Logger")
	}
	if d.Clock == nil {
		missing = append(missing, "Clock")
	}
	if len(missing) > 0 {
		return fmt.Errorf("mcpserver: missing dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

// server carries the dependencies into the tool handlers.
type server struct {
	Deps
	registered []string
	shares     *shareBook
	searches   *rateLimiter
	confirms   *confirmBook
}

// New builds the MCP server with the tools this instance's mode and switches
// allow. A tool that could only ever refuse is not registered at all, so the
// model never plans around a capability it does not have.
func New(deps Deps) (*mcp.Server, []string, error) {
	if err := deps.validate(); err != nil {
		return nil, nil, err
	}
	s := &server{
		Deps: deps, shares: newShareBook(), confirms: newConfirmBook(deps.Clock),
		searches: newRateLimiter(deps.Config.Tuning.FindPerMinute, time.Minute, deps.Clock),
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "vaultwarden-agentic-mcp", Version: deps.Version}, &mcp.ServerOptions{
		Instructions: instructions(deps.Config),
	})
	caps := deps.Config.Caps
	if deps.Config.Mode == config.ModeServer {
		s.registerServerRead(srv)
		if caps.AllowWrite {
			s.registerServerWrite(srv)
			if caps.AllowPermanentDelete {
				s.registerServerDelete(srv)
			}
		}
		return srv, s.registered, nil
	}
	s.registerRead(srv)
	s.registerValues(srv)
	if caps.AllowWrite {
		s.registerWrite(srv)
	}
	if caps.AllowWrite && caps.AllowShare {
		s.registerShare(srv)
	}
	if deps.Config.Mode == config.ModeAdmin {
		s.registerAdminRead(srv)
		if caps.AllowWrite {
			s.registerAdminWrite(srv)
		}
	}
	return srv, s.registered, nil
}

// instructions is the server-level guidance clients show the model once.
func instructions(cfg *config.Config) string {
	if cfg.Mode == config.ModeServer {
		text := "Vaultwarden server administration: the accounts and organizations of the server, through its " +
			"admin panel. No vault contents or secret values are reachable from this instance."
		if !cfg.Caps.AllowWrite {
			text += " This instance is read-only."
		}
		return text
	}
	var b strings.Builder
	b.WriteString("Vaultwarden secrets for agents. Tools return names, metadata and fingerprints, never values, " +
		"unless a tool says otherwise. Items are addressed by name, optionally within a collection; a name that " +
		"matches several items is an error listing their ids.")
	if cfg.Links.Enabled() {
		b.WriteString(" To hand a value to a program, use issue_value_link and fetch the link with curl inside the " +
			"command that needs it (for example `curl -s <url> | gh auth login --with-token`), so the value never " +
			"enters this conversation.")
		if cfg.Caps.AllowWrite {
			b.WriteString(" To receive a value from a human, use request_value_upload and give them the link " +
				"instead of asking them to paste the secret into the chat.")
		}
	} else {
		b.WriteString(" One-time links are disabled on this instance.")
	}
	if !cfg.Caps.AllowReveal {
		b.WriteString(" No tool on this instance returns a value into the conversation.")
	}
	if !cfg.Caps.AllowWrite {
		b.WriteString(" This instance is read-only.")
	}
	return b.String()
}

// Mount adds the MCP endpoint and, when enabled, the one-time link endpoints
// to a mux. auth wraps the MCP endpoint; nil leaves it open, which the
// configuration only allows when asked for explicitly.
func Mount(mux *http.ServeMux, deps Deps, srv *mcp.Server, auth func(http.Handler) http.Handler) {
	if deps.Config.ServesMCPOverHTTP() {
		var handler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		if auth != nil {
			handler = auth(handler)
		}
		mux.Handle("/mcp", handler)
	}
	if deps.Config.Links.Enabled() {
		mux.Handle("/v1/", LinkHandlers(deps))
	}
}

// addTool registers a tool with metrics and audit around it.
func addTool[In, Out any](s *server, srv *mcp.Server, tool *mcp.Tool, handler func(ctx context.Context, call *call, in In) (Out, error)) {
	s.registered = append(s.registered, tool.Name)
	tool.Annotations = annotationsFor(tool.Name)
	mcp.AddTool(srv, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (_ *mcp.CallToolResult, _ Out, err error) {
		c := &call{server: s, tool: tool.Name, principal: s.principal(req)}
		// A panic in one tool must not take down a process holding an
		// unlocked vault; the SDK does not recover handler panics itself.
		defer func() {
			if r := recover(); r != nil {
				s.Logger.Error("panic in tool", slog.String("tool", tool.Name), slog.Any("panic", r), slog.String("stack", string(debug.Stack())))
				s.Metrics.ToolCalls.WithLabelValues(tool.Name, c.principal.Name, obs.OutcomeError).Inc()
				err = errors.New("internal error")
			}
		}()
		out, err := handler(ctx, c, in)
		outcome := obs.OutcomeOK
		if err != nil {
			outcome = obs.OutcomeError
			var zero Out
			out = zero
			err = publicError(err, s.Config.Mode)
		}
		s.Metrics.ToolCalls.WithLabelValues(tool.Name, c.principal.Name, outcome).Inc()
		c.log(ctx, err)
		return nil, out, err
	})
}

func (s *server) principal(req *mcp.CallToolRequest) access.Principal {
	if req != nil && req.Extra != nil {
		if p, ok := access.FromToken(req.Extra.TokenInfo); ok {
			return p
		}
	}
	return s.Local
}

// call is one tool invocation: who called, and what it touched, for the
// audit record written when it returns.
type call struct {
	server    *server
	tool      string
	principal access.Principal
	itemName  string
	itemID    string
	detail    []slog.Attr
	mutation  string
}

func (c *call) touched(it *vault.Item) {
	c.itemName, c.itemID = it.Name, it.ID
}

// note adds an audit attribute. Values never go here.
func (c *call) note(attrs ...slog.Attr) { c.detail = append(c.detail, attrs...) }

func (c *call) mutated(kind string) {
	c.mutation = kind
	c.server.Metrics.Mutations.WithLabelValues(kind).Inc()
}

// log writes the audit record: every mutation, reveal and link at info, plain
// reads at debug.
func (c *call) log(ctx context.Context, err error) {
	attrs := []slog.Attr{slog.String("tool", c.tool), slog.String("client", c.principal.Name)}
	if c.itemID != "" {
		attrs = append(attrs, slog.String("item", c.itemName), slog.String("item_id", c.itemID))
	}
	attrs = append(attrs, c.detail...)
	level := slog.LevelDebug
	if c.mutation != "" || sensitiveTools[c.tool] {
		level = slog.LevelInfo
	}
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
		c.server.Logger.LogAttrs(ctx, slog.LevelWarn, "tool call failed", attrs...)
		return
	}
	c.server.Logger.LogAttrs(ctx, level, "tool call", attrs...)
}

// sensitiveTools are reads that move a value toward someone and so belong in
// the audit trail even when they succeed.
var sensitiveTools = map[string]bool{
	"get_secret": true, "get_attachment": true, "issue_value_link": true,
	"request_value_upload": true, "share_with_human": true, "find_by_value": true,
}

// requireWrite refuses a mutating tool for a read-only client.
func (c *call) requireWrite() error {
	if c.principal.ReadOnly {
		return fmt.Errorf("%w: client %q is read-only", vault.ErrReadOnly, c.principal.Name)
	}
	return nil
}

// snapshot returns the account's view narrowed to what this client may see.
func (c *call) snapshot(ctx context.Context) (*vault.Snapshot, error) {
	snap, err := c.server.Vault.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if c.principal.Unrestricted() {
		return snap, nil
	}
	narrowed := *snap
	narrowed.Collections = nil
	allowed := map[string]bool{}
	for _, col := range snap.Collections {
		if c.principal.AllowsCollection(col.ID, col.Name) {
			narrowed.Collections = append(narrowed.Collections, col)
			allowed[col.ID] = true
		}
	}
	narrowed.Items = nil
	for _, it := range snap.Items {
		if slices.ContainsFunc(it.CollectionIDs, func(id string) bool { return allowed[id] }) {
			narrowed.Items = append(narrowed.Items, it)
		}
	}
	narrowed.Broken = nil
	return &narrowed, nil
}

func (c *call) item(ctx context.Context, ref, collection string, trash bool) (*vault.Snapshot, *vault.Item, error) {
	snap, err := c.snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	it, err := snap.Item(vault.ItemRef{Ref: ref, Collection: collection, Trash: trash})
	if err != nil {
		return nil, nil, err
	}
	c.touched(it)
	return snap, it, nil
}

// collectionIDs resolves collection references within this client's view and
// returns their ids. Writes take the ids, never the names again: resolving a
// name a second time against the whole account could land on a collection
// the client may not touch.
func (c *call) collectionIDs(ctx context.Context, refs []string) ([]string, error) {
	snap, err := c.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		col, err := snap.Collection(ref)
		if err != nil {
			return nil, err
		}
		out = append(out, col.ID)
	}
	return out, nil
}

// publicError marks errors that do not come from the service's own policy as
// failures of the server behind it. Their text is kept because it is what
// makes a failure actionable; transport errors carry no URL (both clients
// strip it) and no error in this service is built from a secret value.
func publicError(err error, mode config.Mode) error {
	switch {
	case errors.Is(err, vault.ErrNotFound), errors.Is(err, vault.ErrAmbiguous), errors.Is(err, vault.ErrInvalid),
		errors.Is(err, vault.ErrReadOnly), errors.Is(err, vault.ErrConflict), errors.Is(err, vault.ErrTooLarge),
		errors.Is(err, vault.ErrUnknownType), errors.Is(err, errDisabled):
		return err
	case mode == config.ModeServer:
		return fmt.Errorf("server: %w", err)
	default:
		return fmt.Errorf("vault: %w", err)
	}
}

// errDisabled marks a request for something this instance does not allow.
var errDisabled = errors.New("disabled on this instance")

// rateLimiter allows a number of events per client in a sliding window. It
// bounds find_by_value: each call tests one guess against every secret, so an
// unbounded rate would make it a guessing oracle.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	seen   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, now: now, seen: map[string][]time.Time{}}
}

// allow records an event for a client and reports whether it is within the
// limit.
func (l *rateLimiter) allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	recent := l.seen[client][:0]
	for _, t := range l.seen[client] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.limit {
		l.seen[client] = recent
		return false
	}
	l.seen[client] = append(recent, now)
	return true
}

// shareBook remembers which client created which share link, so one client
// cannot revoke another's. It lives in memory: after a restart the links still
// expire on their own.
type shareBook struct {
	mu     sync.Mutex
	owners map[string]string
}

func newShareBook() *shareBook { return &shareBook{owners: map[string]string{}} }

func (b *shareBook) add(id, client string) {
	b.mu.Lock()
	b.owners[id] = client
	b.mu.Unlock()
}

// take removes a share the client owns and reports whether it did.
func (b *shareBook) take(id, client string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.owners[id] != client {
		return false
	}
	delete(b.owners, id)
	return true
}
