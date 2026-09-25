package mcpserver_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/access"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/mcpserver"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/obs"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

// harness is one instance of the service on an httptest server, with three
// clients: op (full), ro (read-only) and narrow (collection agents only).
type harness struct {
	t       *testing.T
	url     string
	tokens  map[string]string
	metrics *obs.Metrics
	cfg     *config.Config
}

// enablePermanentDelete flips the switch on a running harness; tools read it
// at call time.
func (h *harness) enablePermanentDelete(t *testing.T) {
	t.Helper()
	h.cfg.Caps.AllowPermanentDelete = true
}

type setup struct {
	serverURL string
	creds     vault.Credentials
	reveal    bool
	mode      config.Mode
	readOnly  bool
	sources   []netip.Prefix
}

func start(t *testing.T, s setup) *harness {
	t.Helper()
	h := &harness{t: t, tokens: map[string]string{}}
	var clients []config.Client
	for _, c := range []struct {
		name string
		ro   bool
		cols []string
	}{{"op", false, nil}, {"ro", true, nil}, {"narrow", false, []string{"agents"}}} {
		token, _, err := access.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		h.tokens[c.name] = token
		clients = append(clients, config.Client{Name: c.name, TokenHash: sha256.Sum256([]byte(token)), ReadOnly: c.ro, Collections: c.cols})
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	h.url = srv.URL

	cfg := &config.Config{
		Account: "test", Mode: s.mode, Transport: config.TransportHTTP,
		Vaultwarden: config.Vaultwarden{URL: s.serverURL, WebURL: s.serverURL},
		Caps:        config.Capabilities{AllowWrite: !s.readOnly, AllowReveal: s.reveal, AllowShare: true},
		Links:       config.Links{PublicURL: srv.URL, TTL: time.Minute, UploadTTL: time.Minute, Sources: s.sources},
		ShareTTL:    time.Hour, MaxShareTTL: 24 * time.Hour,
		Checks:  config.Checks{NotesPrefixes: []string{"Description:"}, ExpiryField: "expires", ExpiryHorizon: 14 * 24 * time.Hour},
		SyncTTL: time.Minute, MaxAttachment: 1 << 20, Clients: clients, Location: time.UTC,
		Tuning: config.Tuning{FindPerMinute: 30, MaxUploadValue: 1 << 20, MaxLinks: 1024, AuthMaxSources: 64},
	}
	h.cfg = cfg
	v, err := vault.New(vault.Config{
		Server:             bitwarden.Config{BaseURL: s.serverURL, Timeout: 30 * time.Second, MaxResponseBytes: 32 << 20},
		Credentials:        s.creds,
		TokenMargin:        5 * time.Minute,
		BackoffMin:         time.Second,
		BackoffMax:         time.Second,
		DeviceName:         "mcp-test",
		SyncTTL:            time.Minute,
		MaxAttachmentBytes: 1 << 20,
		Clock:              time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.metrics = obs.NewMetrics()
	deps := mcpserver.Deps{
		Config: cfg, Vault: v, Links: links.NewStore(time.Now, 1024), Metrics: h.metrics,
		Logger: slog.New(slog.DiscardHandler), Clock: time.Now,
		Local: access.Principal{Name: "local"}, StartedAt: time.Now(), Version: "test",
	}
	server, _, err := mcpserver.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := access.New(access.Config{Clients: clients, MaxFailures: 100, Window: time.Minute, MaxSources: 64, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	mcpserver.Mount(mux, deps, server, guard.Middleware)
	return h
}

func (h *harness) session(ctx context.Context, client string) *mcp.ClientSession {
	h.t.Helper()
	transport := &mcp.StreamableClientTransport{
		Endpoint:   h.url + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token: h.tokens[client], next: http.DefaultTransport}},
		MaxRetries: -1,
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: client, Version: "test"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		h.t.Fatalf("connect %s: %v", client, err)
	}
	h.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call runs a tool and decodes its structured result; wantErr expects a tool
// error whose text contains it.
func call(ctx context.Context, t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any, wantErr string) map[string]any {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	text := b.String()
	if wantErr != "" {
		if !res.IsError || !strings.Contains(text, wantErr) {
			t.Fatalf("%s: want error containing %q, got error=%v %s", tool, wantErr, res.IsError, text)
		}
		return nil
	}
	if res.IsError {
		t.Fatalf("%s failed: %s", tool, text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s: decode %q: %v", tool, text, err)
	}
	return out
}

func toolNames(ctx context.Context, t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func fetch(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }() // the body is fully read or abandoned; a close error changes nothing
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func items(out map[string]any, key string) []any {
	list, _ := out[key].([]any)
	return list
}
