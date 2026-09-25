// Package obs wires the observability surface of the service: structured
// logging, Prometheus metrics and the liveness/readiness probes.
package obs

import (
	"io"
	"log/slog"
)

// NewLogger builds the single JSON logger of the service.
//
// The caller picks the sink: under the http transport logs go to stdout, where
// the container runtime collects them; under stdio that stream carries the
// protocol itself, and a log line there corrupts the session.
func NewLogger(out io.Writer, level slog.Level, attrs ...slog.Attr) *slog.Logger {
	handler := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level}).WithAttrs(attrs)
	return slog.New(handler)
}
