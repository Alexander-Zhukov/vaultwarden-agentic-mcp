// Package config loads the whole service configuration from the environment.
//
// Every setting is overridable by an environment variable. Settings that can
// be guessed carry a documented default and are reported at startup when they
// fall back to it; settings that cannot — which server, as which account — are
// required, and their absence stops the process.
//
// Defaults sit at the safe end of every switch: the consumer mode, read-only,
// values never revealed to the model or shared, permanent deletion off.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// Defaults for every setting that can be guessed.
const (
	DefaultAccount           = "default"
	DefaultMode              = ModeConsumer
	DefaultTransport         = TransportHTTP
	DefaultListenAddr        = ":8080"
	DefaultMetricsAddr       = "-"
	DefaultReadHeaderTime    = 5 * time.Second
	DefaultReadTimeout       = 60 * time.Second
	DefaultWriteTimeout      = 120 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultServerTimeout     = 30 * time.Second
	DefaultMaxResponseBytes  = 64 << 20
	DefaultDeviceName        = "vaultwarden-agentic-mcp"
	DefaultSyncTTL           = 30 * time.Second
	DefaultRefreshInterval   = 5 * time.Minute
	DefaultMaxAttachment     = 10 << 20
	DefaultLinkTTL           = 5 * time.Minute
	DefaultUploadTTL         = 30 * time.Minute
	DefaultShareTTL          = 24 * time.Hour
	DefaultMaxShareTTL       = 7 * 24 * time.Hour
	DefaultExpiryField       = "expires"
	DefaultExpiryHorizon     = 14 * 24 * time.Hour
	DefaultLogLevel          = "info"
	DefaultTimezone          = "UTC"
	DefaultShutdown          = 20 * time.Second
	DefaultMaxAuthFailures   = 10
	DefaultAuthFailureWindow = time.Minute
	DefaultAuthMaxSources    = 4096
	DefaultLoginBackoffMin   = 15 * time.Second
	DefaultLoginBackoffMax   = 2 * time.Minute
	DefaultTokenMargin       = 5 * time.Minute
	DefaultFindPerMinute     = 30
	DefaultMaxUploadValue    = 1 << 20
	DefaultMaxLinks          = 1024
)

// maxSendLifetime is how long Bitwarden-compatible servers keep a Send.
const maxSendLifetime = 31 * 24 * time.Hour

// ErrInvalidEnv is returned when the environment is incomplete or malformed.
var ErrInvalidEnv = errors.New("invalid environment")

// Mode selects which tools the instance registers.
type Mode string

const (
	// ModeConsumer works with the items of the collections the account sees.
	ModeConsumer Mode = "consumer"
	// ModeAdmin adds organization management: members, collections, events.
	ModeAdmin Mode = "admin"
)

// Transport selects how MCP clients reach the server.
type Transport string

const (
	// TransportHTTP serves streamable HTTP, for remote clients.
	TransportHTTP Transport = "http"
	// TransportStdio serves stdin/stdout, for a client that launches the
	// binary as a subprocess.
	TransportStdio Transport = "stdio"
)

// Client is one agent allowed to call the HTTP endpoint. Only the SHA-256 of
// its token is configured, so the environment never holds a usable credential
// for the endpoint.
type Client struct {
	Name      string
	TokenHash [32]byte
	// ReadOnly refuses every tool that changes the vault.
	ReadOnly bool
	// Collections narrows the client to some of the account's collections;
	// empty means all of them. This narrows a client inside one account and
	// is not a security boundary between accounts — that is one account per
	// instance.
	Collections []string
}

// Vaultwarden describes the server and the account.
type Vaultwarden struct {
	URL              string
	WebURL           string
	CAFile           string
	ClientID         string
	ClientSecret     Secret
	Password         Secret
	DeviceName       string
	Timeout          time.Duration
	MaxResponseBytes int64
	// AllowHTTP permits a plain-HTTP server URL, for a server reached over a
	// private container network on the same host.
	AllowHTTP bool
}

// Listen describes the HTTP listener serving MCP, links, health and metrics.
type Listen struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// Capabilities are the switches with a wide blast radius. The service reports
// them through get_status and logs them at startup.
type Capabilities struct {
	AllowReveal          bool
	AllowPermanentDelete bool
	AllowWrite           bool
	// AllowShare registers share_with_human: a Send link is a value leaving
	// to whoever holds the URL, so it is a switch of its own.
	AllowShare bool
	// AllowAdminRoles lets admin mode grant the owner and admin roles.
	AllowAdminRoles bool
	// InviteDomains restricts whom admin mode may invite; empty is anyone.
	InviteDomains []string
}

// LogValue renders capabilities as one structured attribute.
func (c Capabilities) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("allow_reveal", c.AllowReveal),
		slog.Bool("allow_permanent_delete", c.AllowPermanentDelete),
		slog.Bool("allow_write", c.AllowWrite),
		slog.Bool("allow_share", c.AllowShare),
		slog.Bool("allow_admin_roles", c.AllowAdminRoles),
		slog.Any("invite_domains", c.InviteDomains),
	)
}

// Links configures one-time links, the way values reach a process without
// passing through the model.
type Links struct {
	// PublicURL is how clients reach this instance; links are off when empty.
	PublicURL string
	TTL       time.Duration
	UploadTTL time.Duration
	// Sources restricts which addresses may redeem links; empty is any.
	Sources []netip.Prefix
}

// Enabled reports whether one-time links are served.
func (l Links) Enabled() bool { return l.PublicURL != "" }

// Checks configures check_items and the expiry metric.
type Checks struct {
	NotesPrefixes []string
	ExpiryField   string
	ExpiryHorizon time.Duration
}

// Tuning holds operational limits that rarely need changing but must be
// changeable without a rebuild.
type Tuning struct {
	// LoginBackoffMin and LoginBackoffMax bound the wait after a failed
	// login. Servers limit logins per source address, so retrying fast from
	// one instance locks out every client behind that address.
	LoginBackoffMin time.Duration
	LoginBackoffMax time.Duration
	// TokenMargin is how long before expiry an access token is replaced.
	TokenMargin time.Duration
	// FindPerMinute bounds find_by_value per client.
	FindPerMinute int
	// MaxUploadValue bounds a value received through an upload link.
	MaxUploadValue int64
	// MaxLinks bounds outstanding one-time links.
	MaxLinks int
	// AuthMaxSources bounds the table of failing source addresses.
	AuthMaxSources int
}

// Config is the validated configuration of one instance: one account.
type Config struct {
	Account         string
	Mode            Mode
	Organization    string
	Transport       Transport
	Listen          *Listen
	Vaultwarden     Vaultwarden
	Caps            Capabilities
	Links           Links
	ShareTTL        time.Duration
	MaxShareTTL     time.Duration
	Checks          Checks
	SyncTTL         time.Duration
	RefreshInterval time.Duration
	MaxAttachment   int64
	Clients         []Client
	AuthDisabled    bool
	// MetricsAddr, under the http transport, moves /metrics to a listener of
	// its own; empty keeps it on the main listener.
	MetricsAddr     string
	MaxAuthFailures int
	AuthWindow      time.Duration
	Tuning          Tuning
	LogLevel        string
	Location        *time.Location
	Shutdown        time.Duration
}

// SlogLevel returns the configured level.
func (c *Config) SlogLevel() slog.Level { return logLevels[c.LogLevel] }

// ServesMCPOverHTTP reports whether the listener carries the MCP endpoint.
func (c *Config) ServesMCPOverHTTP() bool { return c.Transport == TransportHTTP }

// Load reads and validates the environment, reporting every problem at once.
func Load() (*Config, []string, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom is Load over any source of variables.
func LoadFrom(lookup func(string) (string, bool)) (*Config, []string, error) {
	r := &envReader{lookup: lookup}
	transport := Transport(strings.ToLower(r.stringOr("VWMCP_TRANSPORT", string(DefaultTransport))))

	cfg := &Config{
		Account:      r.stringOr("VWMCP_ACCOUNT", DefaultAccount),
		Mode:         Mode(strings.ToLower(r.stringOr("VWMCP_MODE", string(DefaultMode)))),
		Organization: r.stringOr("VWMCP_ORGANIZATION", ""),
		Transport:    transport,
		Listen:       readListen(r, transport),
		Vaultwarden: Vaultwarden{
			URL:              strings.TrimRight(r.required("VWMCP_SERVER_URL"), "/"),
			CAFile:           r.stringOr("VWMCP_CA_FILE", ""),
			ClientID:         r.required("VWMCP_CLIENT_ID"),
			ClientSecret:     r.requiredSecret("VWMCP_CLIENT_SECRET"),
			Password:         r.requiredSecret("VWMCP_MASTER_PASSWORD"),
			DeviceName:       r.stringOr("VWMCP_DEVICE_NAME", DefaultDeviceName),
			Timeout:          r.durationOr("VWMCP_SERVER_TIMEOUT", DefaultServerTimeout),
			MaxResponseBytes: int64(r.intOr("VWMCP_MAX_RESPONSE_BYTES", DefaultMaxResponseBytes)),
			AllowHTTP:        r.flag("VWMCP_ALLOW_HTTP_SERVER"),
		},
		Caps: Capabilities{
			AllowReveal:          r.flag("VWMCP_ALLOW_REVEAL"),
			AllowPermanentDelete: r.flag("VWMCP_ALLOW_PERMANENT_DELETE"),
			AllowWrite:           r.flag("VWMCP_ALLOW_WRITE"),
			AllowShare:           r.flag("VWMCP_ALLOW_SHARE"),
			AllowAdminRoles:      r.flag("VWMCP_ALLOW_ADMIN_ROLES"),
			InviteDomains:        r.listOr("VWMCP_INVITE_DOMAINS", nil),
		},
		Links: Links{
			PublicURL: strings.TrimRight(r.stringOr("VWMCP_PUBLIC_URL", ""), "/"),
			TTL:       r.durationOr("VWMCP_LINK_TTL", DefaultLinkTTL),
			UploadTTL: r.durationOr("VWMCP_UPLOAD_TTL", DefaultUploadTTL),
		},
		ShareTTL:    r.durationOr("VWMCP_SHARE_TTL", DefaultShareTTL),
		MaxShareTTL: r.durationOr("VWMCP_MAX_SHARE_TTL", DefaultMaxShareTTL),
		Checks: Checks{
			NotesPrefixes: r.listOr("VWMCP_NOTES_PREFIXES", nil),
			ExpiryField:   r.stringOr("VWMCP_EXPIRY_FIELD", DefaultExpiryField),
			ExpiryHorizon: r.durationOr("VWMCP_EXPIRY_HORIZON", DefaultExpiryHorizon),
		},
		SyncTTL:         r.durationOr("VWMCP_SYNC_TTL", DefaultSyncTTL),
		RefreshInterval: r.durationOr("VWMCP_REFRESH_INTERVAL", DefaultRefreshInterval),
		MaxAttachment:   int64(r.intOr("VWMCP_MAX_ATTACHMENT_BYTES", DefaultMaxAttachment)),
		AuthDisabled:    readAuth(r),
		MaxAuthFailures: r.capOr("VWMCP_MAX_AUTH_FAILURES", DefaultMaxAuthFailures),
		Tuning: Tuning{
			LoginBackoffMin: r.durationOr("VWMCP_LOGIN_BACKOFF_MIN", DefaultLoginBackoffMin),
			LoginBackoffMax: r.durationOr("VWMCP_LOGIN_BACKOFF_MAX", DefaultLoginBackoffMax),
			TokenMargin:     r.durationOr("VWMCP_TOKEN_MARGIN", DefaultTokenMargin),
			FindPerMinute:   r.intOr("VWMCP_FIND_PER_MINUTE", DefaultFindPerMinute),
			MaxUploadValue:  int64(r.intOr("VWMCP_MAX_UPLOAD_VALUE_BYTES", DefaultMaxUploadValue)),
			MaxLinks:        r.intOr("VWMCP_MAX_LINKS", DefaultMaxLinks),
			AuthMaxSources:  r.intOr("VWMCP_AUTH_MAX_SOURCES", DefaultAuthMaxSources),
		},
		AuthWindow: r.durationOr("VWMCP_AUTH_FAILURE_WINDOW", DefaultAuthFailureWindow),
		LogLevel:   strings.ToLower(r.stringOr("VWMCP_LOG_LEVEL", DefaultLogLevel)),
		Shutdown:   r.durationOr("VWMCP_SHUTDOWN_TIMEOUT", DefaultShutdown),
	}
	cfg.Vaultwarden.WebURL = strings.TrimRight(r.stringOr("VWMCP_WEB_URL", cfg.Vaultwarden.URL), "/")
	cfg.Links.Sources = readPrefixes(r, "VWMCP_LINK_SOURCES")
	cfg.MetricsAddr = readMetricsAddr(r, transport)
	cfg.Clients = readClients(r)

	zone := r.stringOr("VWMCP_TIMEZONE", DefaultTimezone)
	location, err := time.LoadLocation(zone)
	if err != nil {
		r.fail("VWMCP_TIMEZONE", "unknown time zone")
	} else {
		cfg.Location = location
	}

	cfg.validate(r)
	if err := r.err(); err != nil {
		return nil, nil, err
	}
	return cfg, r.Defaulted(), nil
}

// readAuth reads VWMCP_AUTH: "token" (default) or "none".
func readAuth(r *envReader) bool {
	switch v := strings.ToLower(r.stringOr("VWMCP_AUTH", "token")); v {
	case "token":
		return false
	case "none":
		return true
	default:
		r.fail("VWMCP_AUTH", `must be "token" or "none"`)
		return false
	}
}

// readPrefixes reads a comma-separated list of addresses or CIDR ranges.
func readPrefixes(r *envReader, name string) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range r.listOr(name, nil) {
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		r.fail(name, fmt.Sprintf("%q is neither an address nor a CIDR range", raw))
	}
	return out
}

// readMetricsAddr reads the separate metrics listener of the http transport.
// Under stdio VWMCP_METRICS_ADDR is the only listener and readListen owns it.
func readMetricsAddr(r *envReader, transport Transport) string {
	if transport != TransportHTTP {
		return ""
	}
	addr := r.stringOr("VWMCP_METRICS_ADDR", DefaultMetricsAddr)
	if addr == "-" {
		return ""
	}
	return addr
}

func readListen(r *envReader, transport Transport) *Listen {
	var addr string
	switch transport {
	case TransportHTTP:
		addr = r.stringOr("VWMCP_LISTEN_ADDR", DefaultListenAddr)
	case TransportStdio:
		addr = r.stringOr("VWMCP_METRICS_ADDR", DefaultMetricsAddr)
	default:
		return nil
	}
	if addr == "" || addr == "-" {
		return nil
	}
	return &Listen{
		Addr:              addr,
		ReadHeaderTimeout: r.durationOr("VWMCP_HTTP_READ_HEADER_TIMEOUT", DefaultReadHeaderTime),
		ReadTimeout:       r.durationOr("VWMCP_HTTP_READ_TIMEOUT", DefaultReadTimeout),
		WriteTimeout:      r.durationOr("VWMCP_HTTP_WRITE_TIMEOUT", DefaultWriteTimeout),
		IdleTimeout:       r.durationOr("VWMCP_HTTP_IDLE_TIMEOUT", DefaultIdleTimeout),
	}
}

// readClients parses VWMCP_CLIENTS: entries separated by commas, each
// name:sha256hex[:read_only][:collections=a|b].
func readClients(r *envReader) []Client {
	raw, ok := r.value("VWMCP_CLIENTS")
	if !ok {
		return nil
	}
	var out []Client
	seen := map[string]bool{}
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			// Only the position is named: an entry without a colon may be a
			// token pasted in place of its hash.
			r.fail("VWMCP_CLIENTS", fmt.Sprintf("entry %d: want name:sha256hex[:options]", i+1))
			continue
		}
		c := Client{Name: parts[0]}
		if !validClientName(c.Name) {
			// The name is not echoed: whatever failed the check may be a
			// token pasted into the wrong place.
			r.fail("VWMCP_CLIENTS", fmt.Sprintf("entry %d: a client name is 1-64 letters, digits, '.', '_' or '-'", i+1))
			continue
		}
		if seen[c.Name] {
			r.fail("VWMCP_CLIENTS", fmt.Sprintf("client %q is listed twice", c.Name))
			continue
		}
		seen[c.Name] = true
		sum, err := hex.DecodeString(parts[1])
		if err != nil || len(sum) != sha256.Size {
			r.fail("VWMCP_CLIENTS", fmt.Sprintf("client %q: the token hash must be 64 hex characters of SHA-256", c.Name))
			continue
		}
		copy(c.TokenHash[:], sum)
		for _, opt := range parts[2:] {
			switch {
			case opt == "read_only":
				c.ReadOnly = true
			case strings.HasPrefix(opt, "collections="):
				for _, name := range strings.Split(strings.TrimPrefix(opt, "collections="), "|") {
					if name = strings.TrimSpace(name); name != "" {
						c.Collections = append(c.Collections, name)
					}
				}
				// An empty list would read as "unrestricted", the opposite of
				// what writing the option meant.
				if len(c.Collections) == 0 {
					r.fail("VWMCP_CLIENTS", fmt.Sprintf("client %q: collections= names no collection", c.Name))
				}
			default:
				r.fail("VWMCP_CLIENTS", fmt.Sprintf("client %q: unknown option %q", c.Name, opt))
			}
		}
		out = append(out, c)
	}
	return out
}

func (c *Config) validate(r *envReader) {
	switch c.Mode {
	case ModeConsumer, ModeAdmin:
	default:
		r.fail("VWMCP_MODE", "must be consumer or admin")
	}
	switch c.Transport {
	case TransportHTTP:
		if c.Listen == nil {
			r.fail("VWMCP_LISTEN_ADDR", "cannot be disabled under the http transport")
		}
		if len(c.Clients) == 0 && !c.AuthDisabled {
			r.fail("VWMCP_CLIENTS", `at least one client is required under the http transport; set VWMCP_AUTH=none to run without authentication`)
		}
		if len(c.Clients) > 0 && c.AuthDisabled {
			// Without tokens nobody can be told apart, so every narrowing
			// configured for a client would silently vanish.
			r.fail("VWMCP_AUTH", "none contradicts VWMCP_CLIENTS: remove the clients or keep authentication")
		}
	case TransportStdio:
		if len(c.Clients) > 0 {
			// Nobody presents a token over stdio, so per-client narrowing
			// could never apply.
			r.fail("VWMCP_CLIENTS", "has no effect under the stdio transport; remove it")
		}
		if c.Links.Enabled() && c.Listen == nil {
			r.fail("VWMCP_PUBLIC_URL", "one-time links need an HTTP listener; set VWMCP_METRICS_ADDR under stdio")
		}
	default:
		r.fail("VWMCP_TRANSPORT", "must be http or stdio")
	}
	checkURL(r, "VWMCP_SERVER_URL", c.Vaultwarden.URL, !c.Vaultwarden.AllowHTTP)
	checkURL(r, "VWMCP_WEB_URL", c.Vaultwarden.WebURL, false)
	if c.Links.Enabled() {
		checkURL(r, "VWMCP_PUBLIC_URL", c.Links.PublicURL, false)
	}
	if c.Vaultwarden.ClientID != "" && !strings.HasPrefix(c.Vaultwarden.ClientID, "user.") {
		r.fail("VWMCP_CLIENT_ID", `must be a personal API key id ("user.<uuid>")`)
	}
	if c.Vaultwarden.MaxResponseBytes <= 0 {
		r.fail("VWMCP_MAX_RESPONSE_BYTES", "must be positive")
	}
	if c.MaxAttachment <= 0 {
		r.fail("VWMCP_MAX_ATTACHMENT_BYTES", "must be positive")
	}
	t := c.Tuning
	if t.LoginBackoffMin > t.LoginBackoffMax {
		r.fail("VWMCP_LOGIN_BACKOFF_MIN", "exceeds VWMCP_LOGIN_BACKOFF_MAX")
	}
	for name, v := range map[string]int64{
		"VWMCP_FIND_PER_MINUTE": int64(t.FindPerMinute), "VWMCP_MAX_UPLOAD_VALUE_BYTES": t.MaxUploadValue,
		"VWMCP_MAX_LINKS": int64(t.MaxLinks), "VWMCP_AUTH_MAX_SOURCES": int64(t.AuthMaxSources),
	} {
		if v <= 0 {
			r.fail(name, "must be positive")
		}
	}
	if c.ShareTTL > c.MaxShareTTL {
		r.fail("VWMCP_SHARE_TTL", "exceeds VWMCP_MAX_SHARE_TTL")
	}
	if c.MaxShareTTL > maxSendLifetime {
		r.fail("VWMCP_MAX_SHARE_TTL", "exceeds the 31 days a server keeps a Send")
	}
	if _, ok := logLevels[c.LogLevel]; !ok {
		r.fail("VWMCP_LOG_LEVEL", "must be one of debug, info, warn, error")
	}
}

func checkURL(r *envReader, name, raw string, requireTLS bool) {
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		r.fail(name, "must be an absolute http(s) URL")
		return
	}
	if requireTLS && u.Scheme != "https" && !isLoopback(u.Hostname()) {
		r.fail(name, "must use https, or set VWMCP_ALLOW_HTTP_SERVER=true for a server on a private container network: the API key and every token travel over this connection")
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Warnings lists settings that widen the blast radius, for the startup log.
func (c *Config) Warnings() []string {
	var out []string
	if c.AuthDisabled && c.Transport == TransportHTTP {
		out = append(out, "VWMCP_AUTH=none: the MCP endpoint accepts anyone who can reach it")
	}
	if c.Caps.AllowReveal {
		out = append(out, "VWMCP_ALLOW_REVEAL=true: get_secret returns values into the model context")
	}
	if c.Caps.AllowPermanentDelete {
		out = append(out, "VWMCP_ALLOW_PERMANENT_DELETE=true: items can be destroyed without the trash")
	}
	if c.Caps.AllowShare && c.Caps.AllowWrite {
		out = append(out, "VWMCP_ALLOW_SHARE=true: share_with_human hands values to whoever holds a Send link")
	}
	if c.Mode == ModeAdmin && len(c.Caps.InviteDomains) == 0 && c.Caps.AllowWrite {
		out = append(out, "VWMCP_INVITE_DOMAINS is empty: admin mode may invite any address")
	}
	if c.Mode == ModeAdmin && c.Caps.AllowAdminRoles {
		out = append(out, "VWMCP_ALLOW_ADMIN_ROLES=true: admin mode may grant owner and admin")
	}
	if c.Links.Enabled() && len(c.Links.Sources) == 0 {
		out = append(out, "VWMCP_LINK_SOURCES is empty: one-time links can be redeemed from any address")
	}
	if c.Vaultwarden.AllowHTTP && strings.HasPrefix(c.Vaultwarden.URL, "http://") {
		out = append(out, "VWMCP_ALLOW_HTTP_SERVER=true: the API key and tokens travel to Vaultwarden unencrypted")
	}
	if c.Links.Enabled() && strings.HasPrefix(c.Links.PublicURL, "http://") {
		out = append(out, "VWMCP_PUBLIC_URL is plain http: one-time links carry values unencrypted on the network")
	}
	return out
}

// validClientName accepts names that are safe to show in errors, logs and
// metric labels. The token prefix is refused so a pasted token never passes
// for a name.
func validClientName(name string) bool {
	if name == "" || len(name) > 64 || strings.HasPrefix(name, "vwmcp_") {
		return false
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}
