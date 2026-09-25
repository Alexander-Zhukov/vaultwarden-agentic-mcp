package bitwarden

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		BaseURL: srv.URL, Timeout: 5 * time.Second, MaxResponseBytes: 1024,
		Token: func(context.Context) (string, error) { return "tok", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStatusMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusUnauthorized, `{"message":"no"}`, ErrUnauthorized},
		{http.StatusNotFound, ``, ErrNotFound},
		{http.StatusTooManyRequests, ``, ErrRateLimited},
		{http.StatusBadRequest, `{"message":"Cipher doesn't exist"}`, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			t.Parallel()
			c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			_, err := c.Sync(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAPIErrorCarriesServerMessage(t *testing.T) {
	t.Parallel()
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorModel":{"message":"The client copy of this cipher is out of date."}}`))
	})
	_, err := c.UpdateCipher(context.Background(), "x", Cipher{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, "out of date") {
		t.Fatalf("got %v", err)
	}
}

func TestSendsBearerAndClientHeaders(t *testing.T) {
	t.Parallel()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("Device-Type") == "" || r.Header.Get("Bitwarden-Client-Name") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"profile":{"id":"u"}}`))
	})
	resp, err := c.Sync(context.Background())
	if err != nil || resp.Profile.ID != "u" {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestResponseSizeIsBounded(t *testing.T) {
	t.Parallel()
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"profile":{"id":"` + strings.Repeat("x", 2048) + `"}}`))
	})
	if _, err := c.Sync(context.Background()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestResolveKeepsConfiguredHost(t *testing.T) {
	t.Parallel()
	c, err := New(Config{BaseURL: "http://10.0.0.5:8100", Timeout: time.Second, MaxResponseBytes: 1, Token: func(context.Context) (string, error) { return "", nil }})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ in, want string }{
		{"https://vault.public.test/attachments/c/f?token=abc", "http://10.0.0.5:8100/attachments/c/f?token=abc"},
		{"https://evil.test/steal", "http://10.0.0.5:8100/steal"},
		{"/ciphers/c/attachment/a", "http://10.0.0.5:8100/api/ciphers/c/attachment/a"},
	}
	for _, tt := range tests {
		got, err := c.resolve(tt.in, c.api)
		if err != nil || got != tt.want {
			t.Fatalf("resolve(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestNewValidates(t *testing.T) {
	t.Parallel()
	token := func(context.Context) (string, error) { return "", nil }
	for _, cfg := range []Config{
		{BaseURL: "not a url", Timeout: time.Second, MaxResponseBytes: 1, Token: token},
		{BaseURL: "ftp://x.test", Timeout: time.Second, MaxResponseBytes: 1, Token: token},
		{BaseURL: "https://x.test", Timeout: time.Second, MaxResponseBytes: 1},
		{BaseURL: "https://x.test", Timeout: time.Second, Token: token},
		{BaseURL: "https://x.test", MaxResponseBytes: 1, Token: token},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
}
