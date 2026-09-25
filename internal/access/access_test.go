package access

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

func guardFor(t *testing.T, now *time.Time) (*Guard, string, *int) {
	t.Helper()
	token, _, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	g, err := New(Config{
		Clients:     []config.Client{{Name: "worker", TokenHash: sha256.Sum256([]byte(token)), ReadOnly: true, Collections: []string{"agents"}}},
		MaxFailures: 3, Window: time.Minute, MaxSources: 16,
		Now: func() time.Time { return *now }, OnFailure: func() { failures++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, token, &failures
}

func serve(g *Guard, token, remote string) (int, Principal) {
	var seen Principal
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromToken(auth.TokenInfoFromContext(r.Context()))
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.RemoteAddr = remote
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen
}

func TestGuardAcceptsKnownToken(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	g, token, _ := guardFor(t, &now)
	code, p := serve(g, token, "10.0.0.1:1")
	if code != http.StatusOK || p.Name != "worker" || !p.ReadOnly || !p.AllowsCollection("x", "agents") || p.AllowsCollection("x", "Agents") || p.AllowsCollection("y", "infra") {
		t.Fatalf("code %d principal %+v", code, p)
	}
}

func TestGuardThrottlesFailingSource(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	g, token, failures := guardFor(t, &now)
	for range 3 {
		if code, _ := serve(g, "wrong", "10.0.0.2:1"); code != http.StatusUnauthorized {
			t.Fatalf("bad token got %d", code)
		}
	}
	if code, _ := serve(g, "wrong", "10.0.0.2:1"); code != http.StatusTooManyRequests {
		t.Fatalf("throttled source with a bad token got %d", code)
	}
	// Clients behind one proxy share a source: a valid token still passes.
	if code, _ := serve(g, token, "10.0.0.2:1"); code != http.StatusOK {
		t.Fatalf("throttled source with a valid token got %d", code)
	}
	if code, _ := serve(g, token, "10.0.0.3:1"); code != http.StatusOK {
		t.Fatalf("another source got %d", code)
	}
	if code, _ := serve(g, "", "10.0.0.4:1"); code != http.StatusUnauthorized {
		t.Fatalf("missing token got %d", code)
	}
	now = now.Add(2 * time.Minute)
	if code, _ := serve(g, token, "10.0.0.2:1"); code != http.StatusOK {
		t.Fatalf("after the window got %d", code)
	}
	if *failures != 3 {
		t.Fatalf("failures %d", *failures)
	}
}

func TestNewTokenHashMatches(t *testing.T) {
	t.Parallel()
	token, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	if !strings.HasPrefix(token, "vwmcp_") || len(hash) != 64 || hash != hexOf(sum[:]) {
		t.Fatalf("token %q hash %q", token[:6], hash)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
