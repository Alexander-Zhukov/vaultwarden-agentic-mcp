package obs

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ExpiryCollector counts credentials expired or expiring soon at scrape time,
// from whatever the vault last synced. It exports counts only: which items
// they are is for check_items to say to someone with access, not for a metric
// anyone on the network can read.
type ExpiryCollector struct {
	expiring *prometheus.Desc
	expired  *prometheus.Desc
	horizon  time.Duration
	now      func() time.Time
	source   func() []time.Time
}

// NewExpiryCollector builds the collector. source returns the expiry dates of
// the items that have one and must not block on the network.
func NewExpiryCollector(source func() []time.Time, horizon time.Duration, now func() time.Time) *ExpiryCollector {
	return &ExpiryCollector{
		expiring: prometheus.NewDesc(namespace+"_items_expiring",
			"Items whose expiry date falls within the configured horizon.", nil, nil),
		expired: prometheus.NewDesc(namespace+"_items_expired",
			"Items whose expiry date has passed.", nil, nil),
		horizon: horizon,
		now:     now,
		source:  source,
	}
}

// Describe implements prometheus.Collector.
func (c *ExpiryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.expiring
	ch <- c.expired
}

// Collect implements prometheus.Collector.
func (c *ExpiryCollector) Collect(ch chan<- prometheus.Metric) {
	now := c.now()
	var expiring, expired int
	for _, at := range c.source() {
		switch {
		case !at.After(now):
			expired++
		case at.Sub(now) <= c.horizon:
			expiring++
		}
	}
	ch <- prometheus.MustNewConstMetric(c.expiring, prometheus.GaugeValue, float64(expiring))
	ch <- prometheus.MustNewConstMetric(c.expired, prometheus.GaugeValue, float64(expired))
}
