package obs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestExpiryCollectorCountsOnly(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	m := NewMetrics()
	m.Register(NewExpiryCollector(func() []time.Time {
		return []time.Time{now.Add(-time.Hour), now.Add(24 * time.Hour), now.Add(48 * time.Hour), now.Add(90 * 24 * time.Hour)}
	}, 14*24*time.Hour, func() time.Time { return now }))
	body := scrape(t, m)
	for _, want := range []string{"vaultwarden_mcp_items_expiring 2", "vaultwarden_mcp_items_expired 1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "vaultwarden_mcp_items_expiring{") {
		t.Fatal("the expiry gauges must carry no labels")
	}
}

func TestPrimeAndObserve(t *testing.T) {
	t.Parallel()
	m := NewMetrics()
	m.Prime([]string{"get_item"}, []string{"worker"})
	m.ObserveServer("sync", time.Second, nil)
	m.ObserveServer("sync", time.Second, errors.New("x"))
	m.ObserveLogin(nil)
	body := scrape(t, m)
	for _, want := range []string{
		`vaultwarden_mcp_tools_calls_total{client="worker",outcome="error",tool="get_item"} 0`,
		`vaultwarden_mcp_server_requests_total{operation="sync",outcome="error"} 1`,
		`vaultwarden_mcp_session_logins_total{outcome="ok"} 1`,
		`vaultwarden_mcp_links_events_total{event="issued",kind="upload"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s", want)
		}
	}
}

func TestReadiness(t *testing.T) {
	t.Parallel()
	r := NewReadiness()
	rec := httptest.NewRecorder()
	r.ReadinessHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed gate answered %d", rec.Code)
	}
	r.Set(true)
	rec = httptest.NewRecorder()
	r.ReadinessHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("open gate answered %d", rec.Code)
	}
}
