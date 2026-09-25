// Command vaultwarden-agentic-mcp gives AI agents a Vaultwarden account over the Model
// Context Protocol, built so that secret values stay out of the model's
// context: tools return names, metadata and fingerprints, and values travel to
// programs and humans through one-time links.
//
// One process serves one account. The account's membership in Vaultwarden is
// the boundary of what the instance can reach; agents sharing an instance get
// their own tokens and may be narrowed further.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/errgroup"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/access"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/mcpserver"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/obs"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwadmin"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			if err := runHealthcheck(probeAddr()); err != nil {
				fmt.Fprintf(os.Stderr, "vaultwarden-agentic-mcp healthcheck: %v\n", err)
				os.Exit(1)
			}
			return
		case "token":
			if err := printToken(os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "vaultwarden-agentic-mcp token: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		// The logger may not exist yet when configuration fails.
		fmt.Fprintf(os.Stderr, "vaultwarden-agentic-mcp: %v\n", err)
		os.Exit(1)
	}
}

// printToken prints a new client token and the hash to configure for it.
func printToken(out io.Writer) error {
	token, hash, err := access.NewToken()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "token: %s\nsha256: %s\n\nGive the token to the client; configure only the hash:\nVWMCP_CLIENTS=<name>:%s\n", token, hash, hash)
	return err
}

func run() error {
	cfg, defaulted, err := config.Load()
	if err != nil {
		return err
	}
	logSink := io.Writer(os.Stdout)
	if cfg.Transport == config.TransportStdio {
		logSink = os.Stderr
	}
	logger := obs.NewLogger(logSink, cfg.SlogLevel(), slog.String("service", "vaultwarden-agentic-mcp"), slog.String("account", cfg.Account))
	metrics := obs.NewMetrics()
	readiness := obs.NewReadiness()
	// time.Now keeps its monotonic reading, which every TTL, backoff and
	// window here relies on; the configured zone applies only when a time is
	// shown.
	clock := time.Now
	version := buildVersion()

	logger.Info("starting",
		slog.String("version", version),
		slog.String("mode", string(cfg.Mode)),
		slog.String("transport", string(cfg.Transport)),
		slog.String("server", cfg.Vaultwarden.URL),
		slog.Any("capabilities", cfg.Caps),
		slog.Bool("links", cfg.Links.Enabled()),
		slog.Int("clients", len(cfg.Clients)),
		slog.Any("defaulted", defaulted),
	)
	for _, w := range cfg.Warnings() {
		logger.Warn("wide setting", slog.String("setting", w))
	}

	httpClient, err := serverClient(cfg.Vaultwarden)
	if err != nil {
		return err
	}
	agent := "vaultwarden-agentic-mcp/" + version
	var (
		v     *vault.Vault
		admin *vwadmin.Client
	)
	if cfg.Mode == config.ModeServer {
		admin, err = vwadmin.New(vwadmin.Config{
			BaseURL: cfg.Vaultwarden.URL, Token: cfg.Vaultwarden.AdminToken, HTTP: httpClient,
			MaxResponseBytes: cfg.Vaultwarden.MaxResponseBytes, UserAgent: agent,
			Observe: metrics.ObserveServer, OnLogin: metrics.ObserveLogin,
		})
		if err != nil {
			return err
		}
	} else if v, err = newVault(cfg, httpClient, agent, metrics, clock); err != nil {
		return err
	}

	guard, err := access.New(access.Config{
		Clients: cfg.Clients, MaxFailures: cfg.MaxAuthFailures, Window: cfg.AuthWindow,
		MaxSources: cfg.Tuning.AuthMaxSources, Now: clock, OnFailure: metrics.AuthFailures.Inc,
	})
	if err != nil {
		return err
	}
	local := access.Principal{Name: "local"}
	if cfg.Transport == config.TransportStdio {
		local.Name = "stdio"
	}
	deps := mcpserver.Deps{
		Config: cfg, Vault: v, Admin: admin, Links: links.NewStore(clock, cfg.Tuning.MaxLinks), Metrics: metrics, Logger: logger,
		Clock: clock, Local: local, StartedAt: clock(), Version: version,
	}
	server, tools, err := mcpserver.New(deps)
	if err != nil {
		return err
	}
	metrics.Prime(tools, append(guard.Names(), local.Name))
	logger.Info("tools registered", slog.Any("tools", tools))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	group, ctx := errgroup.WithContext(ctx)
	if admin != nil {
		group.Go(func() error { return keepChecked(ctx, admin, cfg.RefreshInterval, metrics, readiness, logger) })
	} else {
		group.Go(func() error { return keepSynced(ctx, v, cfg.RefreshInterval, metrics, readiness, logger) })
	}

	httpServer := newHTTPServer(cfg, logger, server, guard, deps, metrics, readiness)
	if cfg.MetricsAddr != "" {
		metricsServer := newMetricsServer(cfg, logger, metrics)
		group.Go(func() error {
			logger.Info("serving metrics", slog.String("addr", cfg.MetricsAddr))
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("metrics server: %w", err)
			}
			return nil
		})
		group.Go(func() error {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.Shutdown)
			defer cancel()
			if err := metricsServer.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("metrics shutdown: %w", err)
			}
			return nil
		})
	}
	if httpServer != nil {
		group.Go(func() error {
			logger.Info("listening", slog.String("addr", cfg.Listen.Addr), slog.Bool("serves_mcp", cfg.ServesMCPOverHTTP()))
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("http server: %w", err)
			}
			return nil
		})
		group.Go(func() error {
			<-ctx.Done()
			readiness.Set(false)
			logger.Info("shutting down", slog.Duration("grace", cfg.Shutdown))
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.Shutdown)
			defer cancel()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("graceful shutdown: %w", err)
			}
			return nil
		})
	}
	if cfg.Transport == config.TransportStdio {
		group.Go(func() error {
			logger.Info("serving mcp over stdio")
			err := server.Run(ctx, &mcp.StdioTransport{})
			stop()
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("stdio transport: %w", err)
			}
			return nil
		})
	}

	err = group.Wait()
	logger.Info("stopped")
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// keepSynced syncs at startup and then on an interval, so readiness and the
// expiry metric follow the server even when no agent is calling.
func keepSynced(ctx context.Context, v *vault.Vault, every time.Duration, m *obs.Metrics, ready *obs.Readiness, logger *slog.Logger) error {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		snap, err := v.Refresh(ctx)
		switch {
		case err == nil:
			ready.Set(true)
			m.LastSync.Set(float64(snap.At.Unix()))
			live := 0
			for i := range snap.Items {
				if snap.Items[i].Deleted == nil {
					live++
				}
			}
			m.Items.Set(float64(live))
			m.BrokenItems.Set(float64(len(snap.Broken)))
		case ctx.Err() != nil:
			return nil
		default:
			// The service stays up and keeps retrying; readiness tells the
			// orchestrator and the alert rules that it cannot serve.
			ready.Set(false)
			logger.Warn("sync failed", slog.Any("error", err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// newVault builds the account session of the consumer and admin modes.
func newVault(cfg *config.Config, httpClient *http.Client, agent string, metrics *obs.Metrics, clock func() time.Time) (*vault.Vault, error) {
	v, err := vault.New(vault.Config{
		Server: bitwarden.Config{
			BaseURL: cfg.Vaultwarden.URL, HTTP: httpClient, MaxResponseBytes: cfg.Vaultwarden.MaxResponseBytes,
			Observe: metrics.ObserveServer, UserAgent: agent,
		},
		Credentials: vault.Credentials{
			ClientID:     cfg.Vaultwarden.ClientID,
			ClientSecret: cfg.Vaultwarden.ClientSecret,
			Password:     cfg.Vaultwarden.Password,
		},
		DeviceName:         cfg.Vaultwarden.DeviceName,
		SyncTTL:            cfg.SyncTTL,
		MaxAttachmentBytes: cfg.MaxAttachment,
		Clock:              clock,
		OnLogin:            metrics.ObserveLogin,
		TokenMargin:        cfg.Tuning.TokenMargin,
		BackoffMin:         cfg.Tuning.LoginBackoffMin,
		BackoffMax:         cfg.Tuning.LoginBackoffMax,
	})
	if err != nil {
		return nil, err
	}
	metrics.Register(obs.NewExpiryCollector(expirySource(v, cfg), cfg.Checks.ExpiryHorizon, clock))
	return v, nil
}

// keepChecked is keepSynced of the server mode: it reads the account list at
// startup and on an interval, so readiness tells whether the admin token still
// opens the panel.
func keepChecked(ctx context.Context, admin *vwadmin.Client, every time.Duration, m *obs.Metrics, ready *obs.Readiness, logger *slog.Logger) error {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		_, err := admin.Users(ctx)
		switch {
		case err == nil:
			ready.Set(true)
			m.LastSync.Set(float64(time.Now().Unix()))
		case ctx.Err() != nil:
			return nil
		default:
			ready.Set(false)
			logger.Warn("admin panel check failed", slog.Any("error", err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func expirySource(v *vault.Vault, cfg *config.Config) func() []time.Time {
	return func() []time.Time {
		snap := v.Current()
		if snap == nil || cfg.Checks.ExpiryField == "" {
			return nil
		}
		var out []time.Time
		for i := range snap.Items {
			it := &snap.Items[i]
			if it.Deleted != nil {
				continue
			}
			if at, ok, err := it.Expiry(cfg.Checks.ExpiryField, cfg.Location); err == nil && ok {
				out = append(out, at)
			}
		}
		return out
	}
}

// serverClient builds the HTTP client for Vaultwarden, trusting an extra CA
// when one is configured instead of ever disabling verification.
func serverClient(vw config.Vaultwarden) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if vw.CAFile != "" {
		pem, err := os.ReadFile(vw.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read VWMCP_CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("VWMCP_CA_FILE holds no PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: vw.Timeout, Transport: transport}, nil
}

func newHTTPServer(
	cfg *config.Config, logger *slog.Logger, server *mcp.Server, guard *access.Guard,
	deps mcpserver.Deps, metrics *obs.Metrics, readiness *obs.Readiness,
) *http.Server {
	if cfg.Listen == nil {
		return nil
	}
	mux := http.NewServeMux()
	var auth func(http.Handler) http.Handler
	if !cfg.AuthDisabled {
		auth = guard.Middleware
	}
	mcpserver.Mount(mux, deps, server, auth)
	mux.Handle("GET /health", obs.LivenessHandler())
	mux.Handle("GET /ready", readiness.ReadinessHandler())
	if cfg.MetricsAddr == "" {
		mux.Handle("GET /metrics", metrics.Handler())
	}
	return &http.Server{
		Addr:              cfg.Listen.Addr,
		Handler:           obs.Recover(logger, mux),
		ReadHeaderTimeout: cfg.Listen.ReadHeaderTimeout,
		ReadTimeout:       cfg.Listen.ReadTimeout,
		WriteTimeout:      cfg.Listen.WriteTimeout,
		IdleTimeout:       cfg.Listen.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// newMetricsServer serves /metrics on a listener of its own, for deployments
// that keep item names in the expiry gauge off the network the links use.
func newMetricsServer(cfg *config.Config, logger *slog.Logger, metrics *obs.Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	return &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           obs.Recover(logger, mux),
		ReadHeaderTimeout: cfg.Listen.ReadHeaderTimeout,
		ReadTimeout:       cfg.Listen.ReadTimeout,
		WriteTimeout:      cfg.Listen.WriteTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// probeAddr is the listener the container healthcheck probes: the main one
// under http, the metrics one under stdio.
func probeAddr() string {
	if strings.EqualFold(os.Getenv("VWMCP_TRANSPORT"), string(config.TransportStdio)) {
		return os.Getenv("VWMCP_METRICS_ADDR")
	}
	return os.Getenv("VWMCP_LISTEN_ADDR")
}

// version is set at release builds with -ldflags "-X main.version=<tag>".
var version string

// buildVersion reports the release version, else the VCS revision the
// toolchain stamped into the binary.
func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return "devel"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		return revision + "-dirty"
	}
	return revision
}
