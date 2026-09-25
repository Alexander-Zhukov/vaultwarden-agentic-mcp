package config

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func serverBase() map[string]string {
	return map[string]string{
		"VWMCP_SERVER_URL":  "https://vault.example.test",
		"VWMCP_MODE":        "server",
		"VWMCP_ADMIN_TOKEN": "admin-token",
		"VWMCP_CLIENTS":     "agent:" + hashA,
	}
}

func TestServerMode(t *testing.T) {
	t.Parallel()
	cfg, _, err := load(t, serverBase())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeServer || cfg.Vaultwarden.AdminToken.Reveal() != "admin-token" || cfg.Vaultwarden.ClientID != "" {
		t.Fatalf("server config %+v", cfg.Vaultwarden)
	}
	if !slices.ContainsFunc(cfg.Warnings(), func(w string) bool { return strings.Contains(w, "admin token") }) {
		t.Fatalf("warnings %v", cfg.Warnings())
	}

	tests := []struct {
		name  string
		set   map[string]string
		unset string
		want  string
	}{
		{"no token", nil, "VWMCP_ADMIN_TOKEN", "VWMCP_ADMIN_TOKEN"},
		{"account key", map[string]string{"VWMCP_CLIENT_ID": "user.1"}, "", "VWMCP_CLIENT_ID: has no effect in server mode"},
		{"master password", map[string]string{"VWMCP_MASTER_PASSWORD": "pw"}, "", "VWMCP_MASTER_PASSWORD: has no effect"},
		{"links", map[string]string{"VWMCP_PUBLIC_URL": "https://mcp.example.test"}, "", "VWMCP_PUBLIC_URL: has no effect in server mode"},
		{"reveal", map[string]string{"VWMCP_ALLOW_REVEAL": "true"}, "", "VWMCP_ALLOW_REVEAL"},
		{"organization", map[string]string{"VWMCP_ORGANIZATION": "Machine"}, "", "VWMCP_ORGANIZATION"},
		{"vault tuning", map[string]string{"VWMCP_SYNC_TTL": "10s"}, "", "VWMCP_SYNC_TTL: has no effect in server mode"},
		{"narrowed client", map[string]string{"VWMCP_CLIENTS": "agent:" + hashA + ":collections=infra"}, "", "sees no collections"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := serverBase()
			for k, v := range tt.set {
				env[k] = v
			}
			delete(env, tt.unset)
			_, _, err := load(t, env)
			if !errors.Is(err, ErrInvalidEnv) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
		})
	}
}

func TestAdminTokenOutsideServerMode(t *testing.T) {
	t.Parallel()
	env := base()
	env["VWMCP_ADMIN_TOKEN"] = "admin-token"
	if _, _, err := load(t, env); err == nil || !strings.Contains(err.Error(), "only server mode") {
		t.Fatalf("err %v", err)
	}
}

func TestOrganizationsList(t *testing.T) {
	t.Parallel()
	env := base()
	env["VWMCP_MODE"] = "admin"
	env["VWMCP_ORGANIZATION"] = "Machine, Lab"
	cfg, _, err := load(t, env)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Organizations, []string{"Machine", "Lab"}) {
		t.Fatalf("organizations %v", cfg.Organizations)
	}
}
