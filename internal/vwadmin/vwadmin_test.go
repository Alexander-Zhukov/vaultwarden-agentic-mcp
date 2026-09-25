package vwadmin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// panel is a scriptable admin panel: login answers with loginStatus, and a
// data call answers 401 while refuse is positive.
type panel struct {
	loginStatus atomic.Int32
	logins      atomic.Int32
	refuse      atomic.Int32
	noCookie    atomic.Bool
	session     atomic.Value
}

func newPanel(t *testing.T, routes func(mux *http.ServeMux)) (*panel, *httptest.Server) {
	t.Helper()
	p := &panel{}
	p.loginStatus.Store(http.StatusOK)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin", func(w http.ResponseWriter, r *http.Request) {
		p.logins.Add(1)
		if r.PostFormValue("token") != "right" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status := int(p.loginStatus.Load()); status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if !p.noCookie.Load() {
			session := fmt.Sprintf("s%d", p.logins.Load())
			p.session.Store(session)
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		}
	})
	mux.HandleFunc("GET /admin/users", func(w http.ResponseWriter, r *http.Request) {
		current, _ := p.session.Load().(string)
		if p.refuse.Load() > 0 || r.Header.Get("Cookie") != sessionCookie+"="+current {
			p.refuse.Add(-1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"u1","email":"a@example.test","_status":0,"userEnabled":false,"organizations":[{"id":"o1","name":"Org","type":4,"status":2}]}]`))
	})
	if routes != nil {
		routes(mux)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return p, srv
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func client(t *testing.T, url, token string, clock *fakeClock) *Client {
	t.Helper()
	cfg := Config{BaseURL: url, Token: config.Secret(token), Timeout: 5 * time.Second, MaxResponseBytes: 1 << 16, BackoffMin: time.Minute, BackoffMax: 4 * time.Minute}
	if clock != nil {
		cfg.Clock = clock.Now
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUsersAndRelogin(t *testing.T) {
	t.Parallel()
	p, srv := newPanel(t, nil)
	c := client(t, srv.URL, "right", nil)
	users, err := c.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u := users[0]
	if !u.Disabled() || u.Organizations[0].Type != 4 || u.Organizations[0].Status != 2 {
		t.Fatalf("user %+v", u)
	}
	// A refused session is renewed once.
	p.refuse.Store(1)
	if _, err := c.Users(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := p.logins.Load(); got != 2 {
		t.Fatalf("logins %d, want 2", got)
	}
	// A fresh session refused as well is reported, not retried forever.
	p.refuse.Store(2)
	if _, err := c.Users(context.Background()); !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), "refused as well") {
		t.Fatalf("err %v", err)
	}
}

func TestConcurrentRefusalsShareOneLogin(t *testing.T) {
	t.Parallel()
	p, srv := newPanel(t, nil)
	c := client(t, srv.URL, "right", nil)
	if _, err := c.Users(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.session = "expired"
	c.mu.Unlock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := c.Users(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := p.logins.Load(); got != 2 {
		t.Fatalf("logins %d, want 2: the refused session is renewed once for everyone", got)
	}
}

func TestLoginBackoff(t *testing.T) {
	t.Parallel()
	p, srv := newPanel(t, nil)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	c := client(t, srv.URL, "wrong", clock)
	if _, err := c.Users(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err %v", err)
	}
	if _, err := c.Users(context.Background()); err == nil || !strings.Contains(err.Error(), "next login attempt in 1m0s") {
		t.Fatalf("err %v", err)
	}
	if got := p.logins.Load(); got != 1 {
		t.Fatalf("logins %d during the backoff", got)
	}
	clock.Advance(time.Minute)
	if _, err := c.Users(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err %v", err)
	}
	if _, err := c.Users(context.Background()); err == nil || !strings.Contains(err.Error(), "in 2m0s") {
		t.Fatalf("the backoff did not grow: %v", err)
	}
	c.token = "right"
	clock.Advance(2 * time.Minute)
	if _, err := c.Users(context.Background()); err != nil {
		t.Fatalf("after the backoff: %v", err)
	}
}

func TestLoginFailures(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		status   int
		noCookie bool
		want     string
	}{
		{"rate limited", http.StatusTooManyRequests, false, ErrRateLimited.Error()},
		{"panel disabled", http.StatusNotFound, false, ErrDisabled.Error()},
		{"server error", http.StatusBadGateway, false, "server returned 502"},
		{"no session", http.StatusOK, true, "without a session"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, srv := newPanel(t, nil)
			p.loginStatus.Store(int32(tt.status))
			p.noCookie.Store(tt.noCookie)
			c := client(t, srv.URL, "right", nil)
			if _, err := c.Users(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
		})
	}
}

func TestResponses(t *testing.T) {
	t.Parallel()
	_, srv := newPanel(t, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /admin/users/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Content-Type") != "application/json" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			switch r.PathValue("id") {
			case "json":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"Can't delete last owner"}`))
			case "html":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`<html>secret page</html>`))
			case "redirect":
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(http.StatusSeeOther)
			case "gone":
				w.WriteHeader(http.StatusNotFound)
			case "huge":
				_, _ = w.Write([]byte(strings.Repeat("x", 1<<17)))
			}
		})
		mux.HandleFunc("POST /admin/invite", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"User already exists"}`))
		})
	})
	c := client(t, srv.URL, "right", nil)
	ctx := context.Background()
	for _, tt := range []struct {
		id, want, never string
		is              error
	}{
		{"json", "Can't delete last owner", "", nil},
		{"html", "returned 400", "secret page", nil},
		{"redirect", "with a redirect", "", nil},
		{"gone", "", "", ErrNotFound},
		{"huge", "", "", ErrTooLarge},
	} {
		err := c.ChangeUser(ctx, tt.id, ActionDelete)
		if err == nil || (tt.want != "" && !strings.Contains(err.Error(), tt.want)) || (tt.never != "" && strings.Contains(err.Error(), tt.never)) || (tt.is != nil && !errors.Is(err, tt.is)) {
			t.Fatalf("%s: err %v", tt.id, err)
		}
	}
	if err := c.ChangeUser(ctx, "u1", "explode"); err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("err %v", err)
	}
	if err := c.Invite(ctx, "a@example.test"); err == nil || !strings.Contains(err.Error(), "User already exists") {
		t.Fatalf("err %v", err)
	}
}

func TestTransportErrorCarriesNoURL(t *testing.T) {
	t.Parallel()
	_, srv := newPanel(t, nil)
	c := client(t, srv.URL, "right", nil)
	if _, err := c.Users(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	err := c.ChangeUser(context.Background(), "someone@example.test", ActionDisable)
	if err == nil || strings.Contains(err.Error(), "someone") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("err %v", err)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	withRelease := func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version":"2025.12.0","server":{"name":"Vaultwarden","url":"x"}}`))
		})
		mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`"1.36.0"`)) })
	}
	_, srv := newPanel(t, withRelease)
	v, err := client(t, srv.URL, "right", nil).Version(context.Background())
	if err != nil || v.Release != "1.36.0" || v.API != "2025.12.0" || v.Name != "Vaultwarden" {
		t.Fatalf("version %+v, %v", v, err)
	}
	_, bare := newPanel(t, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version":"2025.12.0","server":{"name":"Vaultwarden"}}`))
		})
	})
	if v, err := client(t, bare.URL, "right", nil).Version(context.Background()); err != nil || v.Release != "" || v.API == "" {
		t.Fatalf("without /api/version %+v, %v", v, err)
	}
}

func TestParseTime(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"2026-09-25 09:58:09 +00:00", "2026-09-25 09:58:09 UTC", "2026-09-25T09:58:09.842496Z"} {
		got, ok := ParseTime(s)
		if !ok || got.UTC().Format(time.DateTime) != "2026-09-25 09:58:09" {
			t.Fatalf("%q -> %v %v", s, got, ok)
		}
	}
	if _, ok := ParseTime("yesterday"); ok {
		t.Fatal("parsed nonsense")
	}
}

func TestNewValidates(t *testing.T) {
	t.Parallel()
	good := Config{BaseURL: "https://vault.example.test", Token: "t", Timeout: time.Second, MaxResponseBytes: 1, BackoffMin: time.Second, BackoffMax: time.Second}
	for name, mutate := range map[string]func(*Config){
		"url":     func(c *Config) { c.BaseURL = "ftp://x" },
		"token":   func(c *Config) { c.Token = "" },
		"limit":   func(c *Config) { c.MaxResponseBytes = 0 },
		"backoff": func(c *Config) { c.BackoffMax = 0 },
		"timeout": func(c *Config) { c.Timeout = 0 },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
}
