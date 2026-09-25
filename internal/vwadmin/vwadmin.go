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

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// Errors a caller must tell apart.
var (
	// ErrUnauthorized means the panel refused the admin token or the session
	// it had just issued.
	ErrUnauthorized = errors.New("admin panel refused access")
	// ErrDisabled means the server has no admin panel: ADMIN_TOKEN is unset.
	ErrDisabled = errors.New("the server's admin panel is disabled")
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
	// BaseURL is the server root, e.g. https://vault.example.com, including
	// the path when the server lives under one.
	BaseURL string
	// Token is the server's ADMIN_TOKEN, in plain form.
	Token config.Secret
	// HTTP is the transport; nil uses a client with Timeout.
	HTTP *http.Client
	// Timeout bounds each request when HTTP is nil.
	Timeout time.Duration
	// MaxResponseBytes bounds every response body read into memory.
	MaxResponseBytes int64
	// BackoffMin and BackoffMax bound the wait after a failed login, which
	// grows between them. The server throttles panel logins (a burst of
	// three, then one per five minutes by default) and logs every refused
	// token, which is what fail2ban watches.
	BackoffMin, BackoffMax time.Duration
	// Clock is the time source for the backoff; nil is time.Now.
	Clock func() time.Time
	// UserAgent identifies this client in server logs.
	UserAgent string
	// Observe receives every request outcome; nil disables it.
	Observe bitwarden.Observer
	// OnLogin is told about every login attempt; nil disables it.
	OnLogin func(err error)
}

// Client is an admin panel client. It is safe for concurrent use.
type Client struct {
	base       string
	token      config.Secret
	http       *http.Client
	maxBody    int64
	agent      string
	observe    bitwarden.Observer
	onLogin    func(error)
	clock      func() time.Time
	backoffMin time.Duration
	backoffMax time.Duration

	mu        sync.Mutex
	session   string
	loginErr  error
	retryAt   time.Time
	nextDelay time.Duration
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
	if cfg.BackoffMin <= 0 || cfg.BackoffMax < cfg.BackoffMin {
		return nil, errors.New("vwadmin: BackoffMin must be positive and not above BackoffMax")
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
		agent: cfg.UserAgent, observe: cfg.Observe, onLogin: cfg.OnLogin, clock: cfg.Clock,
		backoffMin: cfg.BackoffMin, backoffMax: cfg.BackoffMax,
	}
	if c.observe == nil {
		c.observe = func(string, time.Duration, error) {}
	}
	if c.onLogin == nil {
		c.onLogin = func(error) {}
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	return c, nil
}

// Membership is a user's confirmed place in one organization: the panel lists
// no other memberships.
type Membership struct {
	ID     string                 `json:"id"`
	Name   string                 `json:"name"`
	Type   bitwarden.MemberType   `json:"type"`
	Status bitwarden.MemberStatus `json:"status"`
}

// User is an account on the server as the panel's account list reports it.
type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Status    int    `json:"_status"`
	Enabled   *bool  `json:"userEnabled"`
	TwoFactor bool   `json:"twoFactorEnabled"`
	// CreatedAt and LastActive are the panel's own text, in the server's
	// zone; ParseTime reads them.
	CreatedAt     string       `json:"createdAt"`
	LastActive    *string      `json:"lastActive"`
	CreationDate  string       `json:"creationDate"`
	Organizations []Membership `json:"organizations"`
}

// StatusInvited marks an account created by an invitation that nobody has
// registered yet. A disabled account keeps its status; only Enabled says so.
const StatusInvited = 1

// Disabled reports whether the account is disabled.
func (u User) Disabled() bool { return u.Enabled != nil && !*u.Enabled }

// ParseTime reads a time as the panel writes it ("2006-01-02 15:04:05" with a
// zone or offset) or as RFC 3339.
func ParseTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05 -07:00", "2006-01-02 15:04:05 MST", time.RFC3339Nano} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ServerVersion is what the server reports about itself.
type ServerVersion struct {
	// Release is Vaultwarden's own version; empty when the build does not set
	// one.
	Release string
	// API is the Bitwarden API version the server implements.
	API string
	// Name is the server implementation, e.g. Vaultwarden.
	Name string
}

// Users lists every account on the server.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	var out []User
	err := c.call(ctx, "admin_users", http.MethodGet, "/admin/users", nil, &out)
	return out, err
}

// Invite creates an invited account for an address. The person registers
// with that address even when the server refuses open sign-ups.
func (c *Client) Invite(ctx context.Context, email string) error {
	return c.call(ctx, "admin_invite", http.MethodPost, "/admin/invite", map[string]string{"email": email}, nil)
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
	var cfg struct {
		Version string `json:"version"`
		Server  struct {
			Name string `json:"name"`
		} `json:"server"`
	}
	if err := c.public(ctx, "config", "/api/config", &cfg); err != nil {
		return ServerVersion{}, err
	}
	out := ServerVersion{API: cfg.Version, Name: cfg.Server.Name}
	// Older servers do not answer /api/version; the rest still describes them.
	_ = c.public(ctx, "version", "/api/version", &out.Release)
	return out, nil
}

func (c *Client) public(ctx context.Context, op, path string, out any) (err error) {
	start := c.clock()
	defer func() { c.observe(op, c.clock().Sub(start), err) }()
	status, body, err := c.send(ctx, op, http.MethodGet, path, nil, "")
	if err != nil {
		return err
	}
	return decode(op, status, body, out)
}

// login opens a session. The caller holds mu.
func (c *Client) login(ctx context.Context) (err error) {
	start := c.clock()
	defer func() {
		c.observe("admin_login", c.clock().Sub(start), err)
		c.onLogin(err)
	}()
	form := url.Values{"token": {c.token.Reveal()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/admin", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("admin_login: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return transportError("admin_login", err)
	}
	defer func() { _ = resp.Body.Close() }() // drained below; a close error changes nothing
	// The body is the panel's HTML page, of no use here; it is read only so the
	// connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxBody))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("admin_login: %w", ErrRateLimited)
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("admin_login: %w: the admin token was refused", ErrUnauthorized)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("admin_login: %w", ErrDisabled)
	case resp.StatusCode >= 400:
		return fmt.Errorf("admin_login: server returned %d", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			c.session = ck.Value
			return nil
		}
	}
	return fmt.Errorf("admin_login: server answered %d without a session; check VWMCP_SERVER_URL", resp.StatusCode)
}

// call performs an authenticated request, logging in first when there is no
// session and once more when the session was refused.
func (c *Client) call(ctx context.Context, op, method, path string, body, out any) (err error) {
	start := c.clock()
	defer func() { c.observe(op, c.clock().Sub(start), err) }()
	stale := ""
	for attempt := 0; ; attempt++ {
		session, err := c.currentSession(ctx, stale)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		status, raw, err := c.send(ctx, op, method, path, body, session)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			stale = session
			continue
		}
		if status == http.StatusUnauthorized {
			return fmt.Errorf("%s: %w: a new session was refused as well", op, ErrUnauthorized)
		}
		return decode(op, status, raw, out)
	}
}

// currentSession returns the open session, logging in when there is none or
// when the one a request was refused with is still the current one, so
// concurrent requests refused with the same session share one login. After a
// failed login it answers with that failure until the backoff has passed
// instead of trying again.
func (c *Client) currentSession(ctx context.Context, stale string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != "" && c.session != stale {
		return c.session, nil
	}
	c.session = ""
	now := c.clock()
	if c.loginErr != nil && now.Before(c.retryAt) {
		return "", fmt.Errorf("%w (next login attempt in %s)", c.loginErr, c.retryAt.Sub(now).Round(time.Second))
	}
	if err := c.login(ctx); err != nil {
		if ctx.Err() == nil {
			c.nextDelay = min(max(c.nextDelay*2, c.backoffMin), c.backoffMax)
			c.loginErr, c.retryAt = err, now.Add(c.nextDelay)
		}
		return "", err
	}
	c.loginErr, c.nextDelay = nil, 0
	return c.session, nil
}

func (c *Client) send(ctx context.Context, op, method, path string, body any, session string) (int, []byte, error) {
	var reader io.Reader
	if method == http.MethodPost {
		// The panel routes its POST actions by JSON content type; an action
		// without a body still has to announce one.
		payload := []byte("{}")
		if body != nil {
			var err error
			if payload, err = json.Marshal(body); err != nil {
				return 0, nil, fmt.Errorf("%s: encode request: %w", op, err)
			}
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", op, err)
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
		return 0, nil, transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }() // the body is fully read or abandoned; a close error changes nothing
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("%s: read response: %w", op, err)
	}
	if int64(len(raw)) > c.maxBody {
		return 0, nil, fmt.Errorf("%s: %w", op, ErrTooLarge)
	}
	return resp.StatusCode, raw, nil
}

func (c *Client) headers(req *http.Request) {
	if c.agent != "" {
		req.Header.Set("User-Agent", c.agent)
	}
}

// transportError drops the URL from a transport failure: a path can carry an
// email address, and error text travels to logs and to the model.
func transportError(op string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %s: %w", op, ue.Op, ue.Err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// decode maps a response to an error or decodes it into out. Only a JSON
// "message" is ever quoted from an error body; HTML pages are not.
func decode(op string, status int, raw []byte, out any) error {
	switch {
	case status == http.StatusNotFound:
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("%s: %w", op, ErrRateLimited)
	case status >= 400:
		var msg struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &msg) == nil && msg.Message != "" {
			return fmt.Errorf("%s: admin panel returned %d: %s", op, status, msg.Message)
		}
		return fmt.Errorf("%s: admin panel returned %d", op, status)
	case status >= 300:
		return fmt.Errorf("%s: admin panel answered %d with a redirect", op, status)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: decode response: %w", op, err)
	}
	return nil
}
