// Package vwadmin speaks the Vaultwarden admin panel (/admin): the server's
// users and organizations, authenticated by the admin token instead of by an
// account. Nothing here touches vault contents or keys; the panel does not
// have them either.
package vwadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// Errors a caller must tell apart.
var (
	// ErrUnauthorized means the admin token was refused.
	ErrUnauthorized = errors.New("admin token refused")
	// ErrNotFound means the user or organization does not exist.
	ErrNotFound = errors.New("not found")
	// ErrRateLimited means the server throttled the request.
	ErrRateLimited = errors.New("rate limited")
	// ErrTooLarge means a response exceeded the configured size limit.
	ErrTooLarge = errors.New("response too large")
)

// sessionCookie is the cookie the panel issues for a logged-in admin.
const sessionCookie = "VW_ADMIN"

// Config configures a Client.
type Config struct {
	// BaseURL is the server root, e.g. https://vault.example.com.
	BaseURL string
	// Token is the server's ADMIN_TOKEN, in plain form.
	Token config.Secret
	// HTTP is the transport; nil uses a client with Timeout.
	HTTP *http.Client
	// Timeout bounds each request when HTTP is nil.
	Timeout time.Duration
	// MaxResponseBytes bounds every response body read into memory.
	MaxResponseBytes int64
	// UserAgent identifies this client in server logs.
	UserAgent string
	// Observe receives every request outcome; nil disables it.
	Observe func(operation string, duration time.Duration, err error)
	// OnLogin is told about every login attempt; nil disables it.
	OnLogin func(err error)
}

// Client is an admin panel client. It is safe for concurrent use.
type Client struct {
	base    string
	token   config.Secret
	http    *http.Client
	maxBody int64
	agent   string
	observe func(string, time.Duration, error)
	onLogin func(error)

	mu      sync.Mutex
	session string
}

// New validates the configuration and returns a client.
func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("vwadmin: invalid base URL %q", cfg.BaseURL)
	}
	if cfg.Token.IsZero() {
		return nil, errors.New("vwadmin: Token is required")
	}
	if cfg.MaxResponseBytes <= 0 {
		return nil, errors.New("vwadmin: MaxResponseBytes must be positive")
	}
	httpClient := cfg.HTTP
	if httpClient == nil {
		if cfg.Timeout <= 0 {
			return nil, errors.New("vwadmin: Timeout must be positive")
		}
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	// The login answers with the session cookie itself; following a redirect
	// would lose it, and no other call is expected to redirect.
	noRedirect := *httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Client{
		base: base.String(), token: cfg.Token, http: &noRedirect, maxBody: cfg.MaxResponseBytes,
		agent: cfg.UserAgent, observe: cfg.Observe, onLogin: cfg.OnLogin,
	}
	if c.observe == nil {
		c.observe = func(string, time.Duration, error) {}
	}
	if c.onLogin == nil {
		c.onLogin = func(error) {}
	}
	return c, nil
}

// Membership is a user's place in one organization.
type Membership struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   int    `json:"type"`
	Status int    `json:"status"`
}

// User is an account on the server as the panel reports it.
type User struct {
	ID            string       `json:"id"`
	Email         string       `json:"email"`
	Name          string       `json:"name"`
	Status        int          `json:"_status"`
	Enabled       *bool        `json:"userEnabled"`
	EmailVerified bool         `json:"emailVerified"`
	TwoFactor     bool         `json:"twoFactorEnabled"`
	CreatedAt     string       `json:"createdAt"`
	CreationDate  string       `json:"creationDate"`
	LastActive    *string      `json:"lastActive"`
	Organizations []Membership `json:"organizations"`
}

// User statuses as Vaultwarden stores them.
const (
	StatusActive   = 0
	StatusInvited  = 1
	StatusDisabled = 2
)

// ServerVersion is what the server reports about itself: the Bitwarden API
// version it implements and its own name. Vaultwarden does not publish its
// own release number there.
type ServerVersion struct {
	API    string `json:"version"`
	Server struct {
		Name string `json:"name"`
	} `json:"server"`
}

// Users lists every account on the server.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	var out []User
	err := c.call(ctx, "admin_users", http.MethodGet, "/admin/users", nil, &out)
	return out, err
}

// User reads one account by id.
func (c *Client) User(ctx context.Context, id string) (User, error) {
	var out User
	err := c.call(ctx, "admin_user", http.MethodGet, "/admin/users/"+url.PathEscape(id), nil, &out)
	return out, err
}

// UserByEmail reads one account by email address.
func (c *Client) UserByEmail(ctx context.Context, email string) (User, error) {
	var out User
	err := c.call(ctx, "admin_user_by_mail", http.MethodGet, "/admin/users/by-mail/"+url.PathEscape(email), nil, &out)
	return out, err
}

// Invite creates an invited account for an address. The person registers
// with that address even when the server refuses open sign-ups.
func (c *Client) Invite(ctx context.Context, email string) (User, error) {
	var out User
	err := c.call(ctx, "admin_invite", http.MethodPost, "/admin/invite", map[string]string{"email": email}, &out)
	return out, err
}

// UserAction is a lifecycle change of an account.
type UserAction string

// Account lifecycle changes the panel offers.
const (
	ActionDisable      UserAction = "disable"
	ActionEnable       UserAction = "enable"
	ActionDeauthorize  UserAction = "deauth"
	ActionResendInvite UserAction = "invite/resend"
	ActionDelete       UserAction = "delete"
)

// ChangeUser applies a lifecycle change to an account.
func (c *Client) ChangeUser(ctx context.Context, id string, action UserAction) error {
	switch action {
	case ActionDisable, ActionEnable, ActionDeauthorize, ActionResendInvite, ActionDelete:
	default:
		return fmt.Errorf("vwadmin: unknown action %q", action)
	}
	op := "admin_user_" + strings.ReplaceAll(string(action), "/", "_")
	return c.call(ctx, op, http.MethodPost, "/admin/users/"+url.PathEscape(id)+"/"+string(action), nil, nil)
}

// DeleteOrganization removes an organization with everything in it.
func (c *Client) DeleteOrganization(ctx context.Context, id string) error {
	return c.call(ctx, "admin_org_delete", http.MethodPost, "/admin/organizations/"+url.PathEscape(id)+"/delete", nil, nil)
}

// Version reads the server's self-description; it needs no session.
func (c *Client) Version(ctx context.Context) (ServerVersion, error) {
	var out ServerVersion
	start := time.Now()
	status, body, err := c.send(ctx, http.MethodGet, "/api/config", nil, "")
	if err == nil {
		err = decode(status, body, &out)
	}
	c.observe("config", time.Since(start), err)
	return out, err
}

// Login checks the token and opens a session; later calls reuse it.
func (c *Client) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login(ctx)
}

// login opens a session. The caller holds mu.
func (c *Client) login(ctx context.Context) (err error) {
	start := time.Now()
	defer func() {
		c.observe("admin_login", time.Since(start), err)
		c.onLogin(err)
	}()
	form := url.Values{"token": {c.token.Reveal()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/admin", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxBody))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("admin login: %w", ErrRateLimited)
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode >= 400:
		return fmt.Errorf("admin login: server returned %d", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			c.session = ck.Value
			return nil
		}
	}
	return fmt.Errorf("admin login: %w: no session was issued", ErrUnauthorized)
}

// call performs an authenticated request, logging in first when there is no
// session and once more when the session has expired.
func (c *Client) call(ctx context.Context, op, method, path string, body, out any) (err error) {
	start := time.Now()
	defer func() { c.observe(op, time.Since(start), err) }()
	stale := ""
	for attempt := 0; ; attempt++ {
		session, err := c.currentSession(ctx, stale)
		if err != nil {
			return err
		}
		status, raw, err := c.send(ctx, method, path, body, session)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			stale = session
			continue
		}
		return decode(status, raw, out)
	}
}

// currentSession returns the open session, logging in when there is none or
// when the one a request was refused with is still the current one. Logins
// are throttled by the server (three in five minutes by default), so
// concurrent requests refused with the same session share one login.
func (c *Client) currentSession(ctx context.Context, stale string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == "" || c.session == stale {
		c.session = ""
		if err := c.login(ctx); err != nil {
			return "", err
		}
	}
	return c.session, nil
}

func (c *Client) send(ctx context.Context, method, path string, body any, session string) (int, []byte, error) {
	var reader io.Reader
	if method == http.MethodPost {
		// The panel routes its POST actions by JSON content type; an action
		// without a body still has to announce one.
		payload := []byte("{}")
		if body != nil {
			var err error
			if payload, err = json.Marshal(body); err != nil {
				return 0, nil, err
			}
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if session != "" {
		// A request cookie carries only name and value; the attributes belong
		// to the server's Set-Cookie.
		req.Header.Set("Cookie", sessionCookie+"="+session)
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return 0, nil, err
	}
	if int64(len(raw)) > c.maxBody {
		return 0, nil, ErrTooLarge
	}
	return resp.StatusCode, raw, nil
}

func (c *Client) headers(req *http.Request) {
	if c.agent != "" {
		req.Header.Set("User-Agent", c.agent)
	}
}

// decode maps a response to an error or decodes it into out. The panel
// answers errors with HTML pages, so only JSON bodies are ever quoted.
func decode(status int, raw []byte, out any) error {
	switch {
	case status == http.StatusNotFound:
		return ErrNotFound
	case status == http.StatusUnauthorized:
		return ErrUnauthorized
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status >= 400:
		var msg struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &msg) == nil && msg.Message != "" {
			return fmt.Errorf("admin panel returned %d: %s", status, msg.Message)
		}
		return fmt.Errorf("admin panel returned %d", status)
	case status >= 300:
		return fmt.Errorf("admin panel answered %d with a redirect", status)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode admin response: %w", err)
	}
	return nil
}
