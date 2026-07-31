package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authapi_http_requests_total",
			Help: "Total HTTP requests processed, labeled by route, method, and status.",
		},
		[]string{"route", "method", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authapi_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route", "method"},
	)

	LoginAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authapi_login_attempts_total",
			Help: "Login attempts, labeled by result (success/failure).",
		},
		[]string{"result"},
	)

	RefreshReuseDetectedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "authapi_refresh_reuse_detected_total",
			Help: "Number of times refresh token reuse was detected and a token family was revoked.",
		},
	)

	SignupsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authapi_signups_total",
			Help: "Signups, labeled by result (success/failure).",
		},
		[]string{"result"},
	)
)

// Middleware records request count and latency per route/method/status.
// chi.RouteContext gives the matched route pattern (e.g. "/login") rather
// than the raw path, so metrics stay low-cardinality even with path params.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}

		HTTPRequestsTotal.WithLabelValues(route, r.Method, strconv.Itoa(ww.Status())).Inc()
		HTTPRequestDuration.WithLabelValues(route, r.Method).Observe(time.Since(start).Seconds())
	})
}
