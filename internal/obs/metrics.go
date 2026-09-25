package obs

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace prefixes every metric this service exports.
const namespace = "vaultwarden_mcp"

// Outcome labels.
const (
	OutcomeOK    = "ok"
	OutcomeError = "error"
)

// Metrics holds the collectors of the service. Labels stay low-cardinality:
// operation, tool and client names and outcomes — never an item, a collection
// or a value.
type Metrics struct {
	registry *prometheus.Registry

	ServerRequests *prometheus.CounterVec
	ServerDuration *prometheus.HistogramVec
	ToolCalls      *prometheus.CounterVec
	Logins         *prometheus.CounterVec
	LastSync       prometheus.Gauge
	Items          prometheus.Gauge
	BrokenItems    prometheus.Gauge
	Links          *prometheus.CounterVec
	AuthFailures   prometheus.Counter
	Mutations      *prometheus.CounterVec
}

// NewMetrics registers the collectors on a private registry.
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := &Metrics{
		registry: registry,
		ServerRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "server", Name: "requests_total",
			Help: "Requests to the Vaultwarden server by operation and outcome.",
		}, []string{"operation", "outcome"}),
		ServerDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "server", Name: "request_duration_seconds",
			Help: "Duration of requests to the Vaultwarden server by operation.", Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		ToolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "tools", Name: "calls_total",
			Help: "MCP tool calls by tool, client and outcome.",
		}, []string{"tool", "client", "outcome"}),
		Logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "session", Name: "logins_total",
			Help: "Logins to Vaultwarden by outcome.",
		}, []string{"outcome"}),
		LastSync: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "vault", Name: "last_sync_timestamp_seconds",
			Help: "When the vault was last synced successfully.",
		}),
		Items: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "vault", Name: "items",
			Help: "Items visible to the account, trash excluded.",
		}),
		BrokenItems: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "vault", Name: "undecryptable_items",
			Help: "Items the account can see but not decrypt.",
		}),
		Links: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "links", Name: "events_total",
			Help: "One-time links by kind and event (issued, redeemed, rejected).",
		}, []string{"kind", "event"}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "http", Name: "auth_failures_total",
			Help: "Requests to the MCP endpoint refused for an unknown token.",
		}),
		Mutations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "vault", Name: "mutations_total",
			Help: "Changes made to the vault by kind.",
		}, []string{"kind"}),
	}
	registry.MustRegister(m.ServerRequests, m.ServerDuration, m.ToolCalls, m.Logins, m.LastSync,
		m.Items, m.BrokenItems, m.Links, m.AuthFailures, m.Mutations)
	return m
}

// Register adds a collector owned by another package, such as the expiry
// gauge computed from the vault snapshot at scrape time.
func (m *Metrics) Register(c prometheus.Collector) { m.registry.MustRegister(c) }

// Prime creates the series a dashboard expects to see at zero.
func (m *Metrics) Prime(tools, clients []string) {
	for _, outcome := range []string{OutcomeOK, OutcomeError} {
		m.Logins.WithLabelValues(outcome)
		for _, tool := range tools {
			for _, client := range clients {
				m.ToolCalls.WithLabelValues(tool, client, outcome)
			}
		}
	}
	for _, kind := range []string{"value", "attachment", "upload"} {
		for _, event := range []string{"issued", "redeemed", "rejected"} {
			m.Links.WithLabelValues(kind, event)
		}
	}
}

// ObserveServer records one request to Vaultwarden.
func (m *Metrics) ObserveServer(operation string, duration time.Duration, err error) {
	outcome := OutcomeOK
	if err != nil {
		outcome = OutcomeError
	}
	m.ServerRequests.WithLabelValues(operation, outcome).Inc()
	m.ServerDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// ObserveLogin records one login attempt.
func (m *Metrics) ObserveLogin(err error) {
	outcome := OutcomeOK
	if err != nil {
		outcome = OutcomeError
	}
	m.Logins.WithLabelValues(outcome).Inc()
}

// Handler serves the metrics in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}
