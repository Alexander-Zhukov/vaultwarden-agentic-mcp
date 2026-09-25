// Package bitwarden speaks the HTTP API of a Bitwarden-compatible server
// (Vaultwarden or Bitwarden itself): identity, sync, items, collections,
// members, attachments and Sends.
//
// It moves encrypted payloads only. Nothing here decrypts or decides anything;
// the caller owns the keys and the policy.
package bitwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors a caller must tell apart.
var (
	// ErrUnauthorized means the access token was rejected; the caller should
	// log in again rather than retry the same request.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrNotFound means the object does not exist or is not visible to the
	// account — the server does not distinguish the two.
	ErrNotFound = errors.New("not found")
	// ErrRateLimited means the server throttled the request.
	ErrRateLimited = errors.New("rate limited")
	// ErrTooLarge means a response exceeded the configured size limit.
	ErrTooLarge = errors.New("response too large")
)

// APIError carries the status and the server's own message for any other
// failed request.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server returned %d", e.Status)
	}
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Message)
}

// TokenFunc supplies the bearer token for authenticated calls.
type TokenFunc func(ctx context.Context) (string, error)

// Observer is told about every request, for metrics.
type Observer func(operation string, duration time.Duration, err error)

// Config configures a Client.
type Config struct {
	// BaseURL is the server root, e.g. https://vault.example.com.
	BaseURL string
	// HTTP is the transport; nil uses a client with Timeout.
	HTTP *http.Client
	// Timeout bounds each request.
	Timeout time.Duration
	// MaxResponseBytes bounds every response body read into memory.
	MaxResponseBytes int64
	// Token authenticates calls to the API.
	Token TokenFunc
	// Observe receives every request outcome; nil disables it.
	Observe Observer
	// UserAgent identifies this client in server logs.
	UserAgent string
}

// Client is a Bitwarden API client. It is safe for concurrent use.
type Client struct {
	base     *url.URL
	http     *http.Client
	maxBody  int64
	token    TokenFunc
	observe  Observer
	agent    string
	identity string
	api      string
}

// New validates the configuration and returns a client.
func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("bitwarden: invalid base URL %q", cfg.BaseURL)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, fmt.Errorf("bitwarden: unsupported scheme %q", base.Scheme)
	}
	if cfg.Token == nil {
		return nil, errors.New("bitwarden: Token is required")
	}
	if cfg.MaxResponseBytes <= 0 {
		return nil, errors.New("bitwarden: MaxResponseBytes must be positive")
	}
	httpClient := cfg.HTTP
	if httpClient == nil {
		if cfg.Timeout <= 0 {
			return nil, errors.New("bitwarden: Timeout must be positive")
		}
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	observe := cfg.Observe
	if observe == nil {
		observe = func(string, time.Duration, error) {}
	}
	return &Client{
		base:     base,
		http:     httpClient,
		maxBody:  cfg.MaxResponseBytes,
		token:    cfg.Token,
		observe:  observe,
		agent:    cfg.UserAgent,
		identity: base.String() + "/identity",
		api:      base.String() + "/api",
	}, nil
}

// BaseURL returns the server root the client talks to.
func (c *Client) BaseURL() string { return c.base.String() }

type request struct {
	op     string
	method string
	url    string
	body   any
	form   url.Values
	auth   bool
	out    any
}

func (c *Client) do(ctx context.Context, r request) (err error) {
	start := time.Now()
	defer func() { c.observe(r.op, time.Since(start), err) }()

	var body io.Reader
	contentType := ""
	switch {
	case r.form != nil:
		body = strings.NewReader(r.form.Encode())
		contentType = "application/x-www-form-urlencoded; charset=utf-8"
	case r.body != nil:
		data, err := json.Marshal(r.body)
		if err != nil {
			return fmt.Errorf("%s: encode request: %w", r.op, err)
		}
		body = bytes.NewReader(data)
		contentType = "application/json; charset=utf-8"
	}

	req, err := http.NewRequestWithContext(ctx, r.method, r.url, body)
	if err != nil {
		return transportError(r.op+": build request", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.agent != "" {
		req.Header.Set("User-Agent", c.agent)
	}
	// Vaultwarden and Bitwarden both refuse identity requests without the
	// client headers the official clients send.
	req.Header.Set("Bitwarden-Client-Name", "cli")
	req.Header.Set("Bitwarden-Client-Version", clientVersion)
	req.Header.Set("Device-Type", deviceTypeHeader)
	if r.auth {
		token, err := c.token(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", r.op, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.send(req, r.op, r.out)
}

// transportError drops the URL from a transport failure: a signed download
// URL carries a token, and error text travels to logs and to the model.
func transportError(op string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %s: %w", op, ue.Op, ue.Err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func (c *Client) send(req *http.Request, op string, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }() // the body is fully read or abandoned; a close error changes nothing

	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("%s: read response: %w", op, err)
	}
	if int64(len(data)) > c.maxBody {
		return fmt.Errorf("%s: %w", op, ErrTooLarge)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %w", op, statusError(resp.StatusCode, data))
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: decode response: %w", op, err)
	}
	return nil
}

// errorBody covers the error shapes of Vaultwarden, the Bitwarden server and
// the identity endpoint.
type errorBody struct {
	Message          string `json:"message"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorModel       struct {
		Message string `json:"message"`
	} `json:"errorModel"`
}

func statusError(status int, data []byte) error {
	var body errorBody
	_ = json.Unmarshal(data, &body) // a non-JSON error body still yields the status
	message := firstNonEmpty(body.ErrorModel.Message, body.Message, body.ErrorDescription, body.Error)
	apiErr := &APIError{Status: status, Message: message}
	switch status {
	case http.StatusUnauthorized:
		return errors.Join(ErrUnauthorized, apiErr)
	case http.StatusNotFound:
		return errors.Join(ErrNotFound, apiErr)
	case http.StatusTooManyRequests:
		return errors.Join(ErrRateLimited, apiErr)
	default:
		// Vaultwarden answers 400 with "Cipher doesn't exist" and similar for
		// objects outside the account's reach.
		if status == http.StatusBadRequest && strings.Contains(strings.ToLower(message), "doesn't exist") {
			return errors.Join(ErrNotFound, apiErr)
		}
		return apiErr
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// upload posts a multipart body with a single file part.
func (c *Client) upload(ctx context.Context, op, target, fieldName, fileName string, content []byte) (err error) {
	start := time.Now()
	defer func() { c.observe(op, time.Since(start), err) }()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, fileName)
	if err != nil {
		return fmt.Errorf("%s: build form: %w", op, err)
	}
	if _, err := part.Write(content); err != nil {
		return fmt.Errorf("%s: build form: %w", op, err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("%s: build form: %w", op, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &buf)
	if err != nil {
		return transportError(op+": build request", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	token, err := c.token(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.send(req, op, nil)
}

// download fetches raw bytes from a URL the server handed out.
func (c *Client) download(ctx context.Context, op, target string, limit int64) (data []byte, err error) {
	start := time.Now()
	defer func() { c.observe(op, time.Since(start), err) }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, transportError(op+": build request", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }() // the body is fully read or abandoned; a close error changes nothing
	data, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read body: %w", op, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w", op, ErrTooLarge)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: %w", op, statusError(resp.StatusCode, data))
	}
	return data, nil
}

// resolve turns a URL from a response into one on the configured server.
//
// The server builds absolute URLs from its own public name, which is often not
// the address this client uses (a LAN address in front of a public domain), so
// only the path and query are kept. This also means a response can never send
// a request to a third party.
func (c *Client) resolve(ref, prefix string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		// The URL may be signed; the parse error would quote it.
		return "", errors.New("the server returned a URL that does not parse")
	}
	if !u.IsAbs() {
		return prefix + "/" + strings.TrimLeft(ref, "/"), nil
	}
	out := *c.base
	out.Path = u.Path
	out.RawPath = u.RawPath
	out.RawQuery = u.RawQuery
	return out.String(), nil
}
