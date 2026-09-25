package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// errUnhealthy identifies a probe that reached the service and got a failure.
var errUnhealthy = errors.New("service is not healthy")

// healthcheckTimeout bounds the container probe; a slower answer is a failure
// either way.
const healthcheckTimeout = 3 * time.Second

// runHealthcheck probes the local liveness endpoint and reports the result
// through the exit code. The service ships on a distroless image with no shell
// and no curl, so the binary probes itself.
func runHealthcheck(addr string) error {
	if addr == "" {
		addr = config.DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()

	// The target is this process's own listen address, taken from its own
	// configuration and forced to loopback: it is not user-supplied input, so
	// the SSRF warning does not apply.
	url := "http://" + net.JoinHostPort(host, port) + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // self-probe, see comment above
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	client := &http.Client{Timeout: healthcheckTimeout}
	resp, err := client.Do(req) //nolint:gosec // self-probe, see comment above
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }() // the body is fully read or abandoned; a close error changes nothing

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %s", errUnhealthy, url, resp.Status)
	}
	return nil
}
