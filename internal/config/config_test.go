package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var hashA = func() string { s := sha256.Sum256([]byte("a")); return hex.EncodeToString(s[:]) }()

// base is the smallest valid environment.
func base() map[string]string {
	return map[string]string{
		"VWMCP_SERVER_URL":      "https://vault.example.test",
		"VWMCP_CLIENT_ID":       "user.1234",
		"VWMCP_CLIENT_SECRET":   "secret",
		"VWMCP_MASTER_PASSWORD": "pw",
		"VWMCP_CLIENTS":         "agent:" + hashA,
	}
}

func lookupIn(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

func load(t *testing.T, env map[string]string) (*Config, []string, error) {
	t.Helper()
	return LoadFrom(lookupIn(env))
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	cfg, defaulted, err := load(t, base())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeConsumer || cfg.Caps.AllowReveal || cfg.Caps.AllowPermanentDelete || cfg.Caps.AllowWrite ||
		cfg.Caps.AllowShare || cfg.Caps.AllowAdminRoles {
		t.Fatalf("unsafe defaults: %+v %+v", cfg.Mode, cfg.Caps)
	}
	if cfg.Links.Enabled() {
		t.Fatal("links must be off without a public URL")
	}
	if cfg.Vaultwarden.WebURL != cfg.Vaultwarden.URL {
		t.Fatal("web URL defaults to the server URL")
	}
	if len(defaulted) == 0 {
		t.Fatal("defaulted variables must be reported")
	}
	if s := cfg.Vaultwarden.Password.String(); s != redacted {
		t.Fatalf("password printed as %q", s)
	}
}

func TestLoadClients(t *testing.T) {
	t.Parallel()
	env := base()
	env["VWMCP_CLIENTS"] = "worker:" + hashA + ":read_only:collections=agents|infra, ci:" + hashA
	cfg, _, err := load(t, env)
	if err != nil {
		t.Fatal(err)
	}
	sum := [32]byte{}
	copy(sum[:], mustHex(t, hashA))
	want := []Client{
		{Name: "worker", TokenHash: sum, ReadOnly: true, Collections: []string{"agents", "infra"}},
		{Name: "ci", TokenHash: sum},
	}
	if diff := cmp.Diff(want, cfg.Clients); diff != "" {
		t.Fatalf("clients (-want +got):\n%s", diff)
	}
}

func TestLoadRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"missing required", map[string]string{"VWMCP_SERVER_URL": "", "VWMCP_CLIENT_SECRET": ""}, "VWMCP_CLIENT_SECRET"},
		{"plain http server", map[string]string{"VWMCP_SERVER_URL": "http://vault.example.test"}, "must use https"},
		{"bad mode", map[string]string{"VWMCP_MODE": "root"}, "consumer, admin or server"},
		{"no clients", map[string]string{"VWMCP_CLIENTS": ""}, "at least one client"},
		{"bad hash", map[string]string{"VWMCP_CLIENTS": "a:1234"}, "64 hex"},
		{"duplicate client", map[string]string{"VWMCP_CLIENTS": "a:" + hashA + ",a:" + hashA}, "twice"},
		{"unknown option", map[string]string{"VWMCP_CLIENTS": "a:" + hashA + ":admin"}, "unknown option"},
		{"client id shape", map[string]string{"VWMCP_CLIENT_ID": "organization.1"}, "personal API key"},
		{"share ttl over max", map[string]string{"VWMCP_SHARE_TTL": "48h", "VWMCP_MAX_SHARE_TTL": "24h"}, "exceeds"},
		{"links under stdio need a listener", map[string]string{"VWMCP_TRANSPORT": "stdio", "VWMCP_PUBLIC_URL": "http://x.test"}, "VWMCP_METRICS_ADDR"},
		{"auth none with clients", map[string]string{"VWMCP_AUTH": "none"}, "contradicts"},
		{"unknown auth", map[string]string{"VWMCP_AUTH": "basic"}, `"token" or "none"`},
		{"empty collections option", map[string]string{"VWMCP_CLIENTS": "a:" + hashA + ":collections="}, "names no collection"},
		{"send lifetime", map[string]string{"VWMCP_MAX_SHARE_TTL": "800h"}, "31 days"},
		{"bad link source", map[string]string{"VWMCP_LINK_SOURCES": "10.0.0.0/33"}, "CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := base()
			for k, v := range tt.set {
				env[k] = v
			}
			_, _, err := load(t, env)
			if !errors.Is(err, ErrInvalidEnv) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	t.Parallel()
	_, _, err := load(t, map[string]string{"VWMCP_MODE": "x"})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, name := range []string{"VWMCP_SERVER_URL", "VWMCP_CLIENT_ID", "VWMCP_MASTER_PASSWORD", "VWMCP_MODE"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("%s missing from %v", name, err)
		}
	}
}

func TestMalformedClientEntryHidesToken(t *testing.T) {
	t.Parallel()
	env := base()
	env["VWMCP_CLIENTS"] = "vwmcp_pasted-token-by-mistake"
	_, _, err := load(t, env)
	if err == nil || strings.Contains(err.Error(), "pasted-token") {
		t.Fatalf("error leaks the entry: %v", err)
	}
}

func TestWarnings(t *testing.T) {
	t.Parallel()
	env := base()
	env["VWMCP_AUTH"] = "none"
	env["VWMCP_CLIENTS"] = ""
	env["VWMCP_ALLOW_REVEAL"] = "true"
	env["VWMCP_ALLOW_HTTP_SERVER"] = "true"
	env["VWMCP_SERVER_URL"] = "http://vaultwarden"
	env["VWMCP_PUBLIC_URL"] = "http://10.0.0.1:8080"
	cfg, _, err := load(t, env)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Warnings()); got != 5 {
		t.Fatalf("warnings %v", cfg.Warnings())
	}
}

func TestLinkSources(t *testing.T) {
	t.Parallel()
	env := base()
	env["VWMCP_LINK_SOURCES"] = "198.51.100.0/24, 203.0.113.7"
	cfg, _, err := load(t, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Links.Sources) != 2 || cfg.Links.Sources[1].Bits() != 32 {
		t.Fatalf("sources %v", cfg.Links.Sources)
	}
}

// tokenShaped matches what `vaultwarden-agentic-mcp token` prints.
var tokenShaped = regexp.MustCompile(`vwmcp_[A-Za-z0-9_-]{20,}`)

func FuzzReadClients(f *testing.F) {
	f.Add("agent:" + hashA)
	f.Add("a:" + hashA + ":read_only:collections=x|y, b:" + hashA)
	f.Add("vwmcp_token-pasted-here-by-mistake-0123")
	f.Add("vwmcp_token-pasted-here-by-mistake-0123:" + hashA)
	f.Add(":::,,,")
	f.Fuzz(func(t *testing.T, raw string) {
		r := &envReader{lookup: lookupIn(map[string]string{"VWMCP_CLIENTS": raw})}
		for _, c := range readClients(r) {
			if c.Name == "" {
				t.Fatal("a client without a name was accepted")
			}
		}
		// A malformed entry is reported without echoing anything that might
		// be a token pasted in place of its hash.
		if err := r.err(); err != nil {
			for _, token := range tokenShaped.FindAllString(raw, -1) {
				if strings.Contains(err.Error(), token) {
					t.Fatalf("error echoes a token: %v", err)
				}
			}
		}
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
