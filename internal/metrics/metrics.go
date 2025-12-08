package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all application metrics.
type Metrics struct {
	BundlesLoaded    prometheus.Counter
	ProfilesAnalyzed prometheus.Counter
	ActiveProfiles   prometheus.Gauge
	RequestDuration  *prometheus.HistogramVec
}

// New creates and registers all application metrics.
func New() *Metrics {
	m := &Metrics{
		BundlesLoaded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "coder_bundle_helper_bundles_loaded_total",
			Help: "Total number of bundles loaded",
		}),
		ProfilesAnalyzed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "coder_bundle_helper_profiles_analyzed_total",
			Help: "Total number of profiles analyzed",
		}),
		ActiveProfiles: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "coder_bundle_helper_active_pprof_instances",
			Help: "Number of active pprof instances",
		}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "coder_bundle_helper_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"handler", "method"}),
	}

	prometheus.MustRegister(m.BundlesLoaded, m.ProfilesAnalyzed, m.ActiveProfiles, m.RequestDuration)
	return m
}

// WithMetrics wraps an HTTP handler with request duration metrics.
func (m *Metrics) WithMetrics(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h(w, r)
		m.RequestDuration.WithLabelValues(name, r.Method).Observe(time.Since(start).Seconds())
	}
}
