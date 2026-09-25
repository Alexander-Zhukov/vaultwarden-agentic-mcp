// Package access authenticates the agents calling the MCP endpoint and carries
// who they are into the tools.
//
// Each client presents its own bearer token; only the SHA-256 of a token is
// configured. A client may be narrowed to read-only use or to some of the
// account's collections — a restriction inside one account, not a boundary
// between accounts.
package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// Principal is the caller of a tool.
type Principal struct {
	Name        string
	ReadOnly    bool
	Collections []string
}

// Unrestricted reports whether the principal sees every collection.
func (p Principal) Unrestricted() bool { return len(p.Collections) == 0 }

// AllowsCollection reports whether the principal may use a collection, by id
// or exact name. The match is exact on purpose: a collection created later
// under a name differing only in case must not widen a client's reach.
func (p Principal) AllowsCollection(id, name string) bool {
	if p.Unrestricted() {
		return true
	}
	return slices.ContainsFunc(p.Collections, func(c string) bool { return c == id || c == name })
}

// principalKey is where the principal travels in TokenInfo.Extra.
const principalKey = "principal"

// ErrUnknownToken is what an unrecognised token yields.
var ErrUnknownToken = errors.New("unknown token")

// FromToken recovers the principal the middleware attached to a request.
func FromToken(info *auth.TokenInfo) (Principal, bool) {
	if info == nil {
		return Principal{}, false
	}
	p, ok := info.Extra[principalKey].(Principal)
	return p, ok
}

// Guard verifies tokens and throttles sources that keep failing.
type Guard struct {
	clients   map[[32]byte]Principal
	limiter   *limiter
	onFailure func()
}

// Config assembles a Guard.
type Config struct {
	Clients []config.Client
	// MaxFailures per source and Window throttle failing sources; zero
	// MaxFailures disables throttling.
	MaxFailures int
	Window      time.Duration
	// MaxSources bounds the table of failing sources.
	MaxSources int
	Now        func() time.Time
	// OnFailure is told about every refused token, for metrics.
	OnFailure func()
}

// New validates the configuration and builds a guard.
func New(cfg Config) (*Guard, error) {
	if cfg.MaxFailures > 0 && (cfg.Window <= 0 || cfg.MaxSources <= 0 || cfg.Now == nil) {
		return nil, errors.New("access: throttling needs a window, a source bound and a clock")
	}
	g := &Guard{clients: map[[32]byte]Principal{}, onFailure: cfg.OnFailure}
	for _, c := range cfg.Clients {
		g.clients[c.TokenHash] = Principal{Name: c.Name, ReadOnly: c.ReadOnly, Collections: slices.Clone(c.Collections)}
	}
	if cfg.MaxFailures > 0 {
		g.limiter = &limiter{max: cfg.MaxFailures, window: cfg.Window, now: cfg.Now, maxSources: cfg.MaxSources, seen: map[string]*bucket{}}
	}
	if g.onFailure == nil {
		g.onFailure = func() {}
	}
	return g, nil
}

// Names lists the configured clients, for priming metrics.
func (g *Guard) Names() []string {
	out := make([]string, 0, len(g.clients))
	for _, p := range g.clients {
		out = append(out, p.Name)
	}
	slices.Sort(out)
	return out
}

func (g *Guard) verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	sum := sha256.Sum256([]byte(token))
	p, ok := g.clients[sum]
	if !ok {
		g.onFailure()
		return nil, fmt.Errorf("%w: %w", auth.ErrInvalidToken, ErrUnknownToken)
	}
	// UserID binds a session to its client: a session id seen by another
	// client's token is refused by the transport.
	return &auth.TokenInfo{UserID: p.Name, Extra: map[string]any{principalKey: p}}, nil
}

// Middleware authenticates requests to the MCP endpoint.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	checked := auth.RequireBearerToken(g.verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(next)
	if g.limiter == nil {
		return checked
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := sourceOf(r)
		// A throttled source is still let through with a valid token: every
		// client behind one proxy address shares the source, and one of them
		// holding a stale token must not lock the others out.
		if g.limiter.blocked(source) && !g.known(r) {
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		checked.ServeHTTP(rec, r)
		if rec.status == http.StatusUnauthorized {
			g.limiter.fail(source)
		}
	})
}

// known reports whether the request carries a configured token.
func (g *Guard) known(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	_, found := g.clients[sha256.Sum256([]byte(token))]
	return found
}

func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush keeps streaming responses streaming through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// limiter counts failures per source in fixed windows. The table is bounded:
// past maxSources the expired windows are dropped, so a scan from many
// addresses cannot grow memory without limit.
type limiter struct {
	mu         sync.Mutex
	max        int
	window     time.Duration
	now        func() time.Time
	maxSources int
	seen       map[string]*bucket
}

type bucket struct {
	start time.Time
	count int
}

func (l *limiter) blocked(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.seen[source]
	if !ok {
		return false
	}
	if l.now().Sub(b.start) > l.window {
		delete(l.seen, source)
		return false
	}
	return b.count >= l.max
}

func (l *limiter) fail(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.seen[source]
	if !ok || now.Sub(b.start) > l.window {
		if len(l.seen) >= l.maxSources {
			for k, v := range l.seen {
				if now.Sub(v.start) > l.window {
					delete(l.seen, k)
				}
			}
		}
		if len(l.seen) >= l.maxSources {
			return
		}
		b = &bucket{start: now}
		l.seen[source] = b
	}
	b.count++
}

// NewToken returns a fresh client token and the hash to configure for it.
func NewToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("read random token: %w", err)
	}
	token = "vwmcp_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}
