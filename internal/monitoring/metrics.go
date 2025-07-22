package monitoring

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics contains all Prometheus metrics for the authentication system
type Metrics struct {
	// Authentication metrics
	AuthAttempts     *prometheus.CounterVec
	AuthSuccesses    *prometheus.CounterVec
	AuthFailures     *prometheus.CounterVec
	AuthDuration     *prometheus.HistogramVec
	TokenGenerations *prometheus.CounterVec
	TokenValidations *prometheus.CounterVec
	TokenRefreshes   *prometheus.CounterVec

	// User management metrics
	UserRegistrations *prometheus.CounterVec
	UserLogins        *prometheus.CounterVec
	UserLogouts       *prometheus.CounterVec
	ProfileUpdates    *prometheus.CounterVec

	// MFA metrics
	MFAAttempts  *prometheus.CounterVec
	MFASuccesses *prometheus.CounterVec
	MFAFailures  *prometheus.CounterVec

	// Database metrics
	DatabaseConnections   *prometheus.GaugeVec
	DatabaseQueries       *prometheus.CounterVec
	DatabaseQueryDuration *prometheus.HistogramVec
	DatabaseErrors        *prometheus.CounterVec

	// Cache metrics
	CacheHits              *prometheus.CounterVec
	CacheMisses            *prometheus.CounterVec
	CacheOperations        *prometheus.CounterVec
	CacheOperationDuration *prometheus.HistogramVec

	// Rate limiting metrics
	RateLimitHits   *prometheus.CounterVec
	RateLimitBlocks *prometheus.CounterVec

	// HTTP metrics
	HTTPRequests     *prometheus.CounterVec
	HTTPDuration     *prometheus.HistogramVec
	HTTPRequestSize  *prometheus.HistogramVec
	HTTPResponseSize *prometheus.HistogramVec

	// gRPC metrics
	GRPCRequests *prometheus.CounterVec
	GRPCDuration *prometheus.HistogramVec

	// System metrics
	ActiveSessions *prometheus.GaugeVec
	SystemHealth   *prometheus.GaugeVec
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		// Authentication metrics
		AuthAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_attempts_total",
				Help: "Total number of authentication attempts",
			},
			[]string{"method", "result"},
		),
		AuthSuccesses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_successes_total",
				Help: "Total number of successful authentications",
			},
			[]string{"method", "user_type"},
		),
		AuthFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_failures_total",
				Help: "Total number of failed authentications",
			},
			[]string{"method", "reason"},
		),
		AuthDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_duration_seconds",
				Help:    "Duration of authentication operations",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "result"},
		),
		TokenGenerations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "token_generations_total",
				Help: "Total number of token generations",
			},
			[]string{"token_type"},
		),
		TokenValidations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "token_validations_total",
				Help: "Total number of token validations",
			},
			[]string{"token_type", "result"},
		),
		TokenRefreshes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "token_refreshes_total",
				Help: "Total number of token refreshes",
			},
			[]string{"result"},
		),

		// User management metrics
		UserRegistrations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "user_registrations_total",
				Help: "Total number of user registrations",
			},
			[]string{"method"},
		),
		UserLogins: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "user_logins_total",
				Help: "Total number of user logins",
			},
			[]string{"method"},
		),
		UserLogouts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "user_logouts_total",
				Help: "Total number of user logouts",
			},
			[]string{},
		),
		ProfileUpdates: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "profile_updates_total",
				Help: "Total number of profile updates",
			},
			[]string{"field"},
		),

		// MFA metrics
		MFAAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mfa_attempts_total",
				Help: "Total number of MFA attempts",
			},
			[]string{"method"},
		),
		MFASuccesses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mfa_successes_total",
				Help: "Total number of successful MFA verifications",
			},
			[]string{"method"},
		),
		MFAFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mfa_failures_total",
				Help: "Total number of failed MFA verifications",
			},
			[]string{"method", "reason"},
		),

		// Database metrics
		DatabaseConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "database_connections",
				Help: "Current number of database connections",
			},
			[]string{"state"}, // active, idle, max
		),
		DatabaseQueries: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "database_queries_total",
				Help: "Total number of database queries",
			},
			[]string{"operation", "table"},
		),
		DatabaseQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "database_query_duration_seconds",
				Help:    "Duration of database queries",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"operation", "table"},
		),
		DatabaseErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "database_errors_total",
				Help: "Total number of database errors",
			},
			[]string{"operation", "error_type"},
		),

		// Cache metrics
		CacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"cache_type", "operation"},
		),
		CacheMisses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"cache_type", "operation"},
		),
		CacheOperations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_operations_total",
				Help: "Total number of cache operations",
			},
			[]string{"cache_type", "operation", "result"},
		),
		CacheOperationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "cache_operation_duration_seconds",
				Help:    "Duration of cache operations",
				Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
			},
			[]string{"cache_type", "operation"},
		),

		// Rate limiting metrics
		RateLimitHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rate_limit_hits_total",
				Help: "Total number of rate limit hits",
			},
			[]string{"limiter_type", "identifier"},
		),
		RateLimitBlocks: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rate_limit_blocks_total",
				Help: "Total number of rate limit blocks",
			},
			[]string{"limiter_type", "identifier"},
		),

		// HTTP metrics
		HTTPRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		HTTPDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Duration of HTTP requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint", "status_code"},
		),
		HTTPRequestSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_size_bytes",
				Help:    "Size of HTTP requests",
				Buckets: []float64{100, 1000, 10000, 100000, 1000000},
			},
			[]string{"method", "endpoint"},
		),
		HTTPResponseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Size of HTTP responses",
				Buckets: []float64{100, 1000, 10000, 100000, 1000000},
			},
			[]string{"method", "endpoint", "status_code"},
		),

		// gRPC metrics
		GRPCRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "grpc_requests_total",
				Help: "Total number of gRPC requests",
			},
			[]string{"service", "method", "status_code"},
		),
		GRPCDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "grpc_request_duration_seconds",
				Help:    "Duration of gRPC requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"service", "method", "status_code"},
		),

		// System metrics
		ActiveSessions: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "active_sessions",
				Help: "Current number of active sessions",
			},
			[]string{"session_type"},
		),
		SystemHealth: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "system_health",
				Help: "System health status (1=healthy, 0=unhealthy)",
			},
			[]string{"component"},
		),
	}

	// Register all metrics
	registry.MustRegister(
		m.AuthAttempts,
		m.AuthSuccesses,
		m.AuthFailures,
		m.AuthDuration,
		m.TokenGenerations,
		m.TokenValidations,
		m.TokenRefreshes,
		m.UserRegistrations,
		m.UserLogins,
		m.UserLogouts,
		m.ProfileUpdates,
		m.MFAAttempts,
		m.MFASuccesses,
		m.MFAFailures,
		m.DatabaseConnections,
		m.DatabaseQueries,
		m.DatabaseQueryDuration,
		m.DatabaseErrors,
		m.CacheHits,
		m.CacheMisses,
		m.CacheOperations,
		m.CacheOperationDuration,
		m.RateLimitHits,
		m.RateLimitBlocks,
		m.HTTPRequests,
		m.HTTPDuration,
		m.HTTPRequestSize,
		m.HTTPResponseSize,
		m.GRPCRequests,
		m.GRPCDuration,
		m.ActiveSessions,
		m.SystemHealth,
	)

	return m
}

// RecordAuthAttempt records an authentication attempt
func (m *Metrics) RecordAuthAttempt(method, result string) {
	m.AuthAttempts.WithLabelValues(method, result).Inc()
}

// RecordAuthSuccess records a successful authentication
func (m *Metrics) RecordAuthSuccess(method, userType string) {
	m.AuthSuccesses.WithLabelValues(method, userType).Inc()
}

// RecordAuthFailure records a failed authentication
func (m *Metrics) RecordAuthFailure(method, reason string) {
	m.AuthFailures.WithLabelValues(method, reason).Inc()
}

// RecordAuthDuration records the duration of an authentication operation
func (m *Metrics) RecordAuthDuration(method, result string, duration time.Duration) {
	m.AuthDuration.WithLabelValues(method, result).Observe(duration.Seconds())
}

// RecordTokenGeneration records a token generation
func (m *Metrics) RecordTokenGeneration(tokenType string) {
	m.TokenGenerations.WithLabelValues(tokenType).Inc()
}

// RecordTokenValidation records a token validation
func (m *Metrics) RecordTokenValidation(tokenType, result string) {
	m.TokenValidations.WithLabelValues(tokenType, result).Inc()
}

// RecordTokenRefresh records a token refresh
func (m *Metrics) RecordTokenRefresh(result string) {
	m.TokenRefreshes.WithLabelValues(result).Inc()
}

// RecordUserRegistration records a user registration
func (m *Metrics) RecordUserRegistration(method string) {
	m.UserRegistrations.WithLabelValues(method).Inc()
}

// RecordUserLogin records a user login
func (m *Metrics) RecordUserLogin(method string) {
	m.UserLogins.WithLabelValues(method).Inc()
}

// RecordUserLogout records a user logout
func (m *Metrics) RecordUserLogout() {
	m.UserLogouts.WithLabelValues().Inc()
}

// RecordProfileUpdate records a profile update
func (m *Metrics) RecordProfileUpdate(field string) {
	m.ProfileUpdates.WithLabelValues(field).Inc()
}

// RecordMFAAttempt records an MFA attempt
func (m *Metrics) RecordMFAAttempt(method string) {
	m.MFAAttempts.WithLabelValues(method).Inc()
}

// RecordMFASuccess records a successful MFA verification
func (m *Metrics) RecordMFASuccess(method string) {
	m.MFASuccesses.WithLabelValues(method).Inc()
}

// RecordMFAFailure records a failed MFA verification
func (m *Metrics) RecordMFAFailure(method, reason string) {
	m.MFAFailures.WithLabelValues(method, reason).Inc()
}

// RecordDatabaseConnections records current database connections
func (m *Metrics) RecordDatabaseConnections(active, idle, max int) {
	m.DatabaseConnections.WithLabelValues("active").Set(float64(active))
	m.DatabaseConnections.WithLabelValues("idle").Set(float64(idle))
	m.DatabaseConnections.WithLabelValues("max").Set(float64(max))
}

// RecordDatabaseQuery records a database query
func (m *Metrics) RecordDatabaseQuery(operation, table string, duration time.Duration) {
	m.DatabaseQueries.WithLabelValues(operation, table).Inc()
	m.DatabaseQueryDuration.WithLabelValues(operation, table).Observe(duration.Seconds())
}

// RecordDatabaseError records a database error
func (m *Metrics) RecordDatabaseError(operation, errorType string) {
	m.DatabaseErrors.WithLabelValues(operation, errorType).Inc()
}

// RecordCacheHit records a cache hit
func (m *Metrics) RecordCacheHit(cacheType, operation string) {
	m.CacheHits.WithLabelValues(cacheType, operation).Inc()
}

// RecordCacheMiss records a cache miss
func (m *Metrics) RecordCacheMiss(cacheType, operation string) {
	m.CacheMisses.WithLabelValues(cacheType, operation).Inc()
}

// RecordCacheOperation records a cache operation
func (m *Metrics) RecordCacheOperation(cacheType, operation, result string, duration time.Duration) {
	m.CacheOperations.WithLabelValues(cacheType, operation, result).Inc()
	m.CacheOperationDuration.WithLabelValues(cacheType, operation).Observe(duration.Seconds())
}

// RecordRateLimitHit records a rate limit hit
func (m *Metrics) RecordRateLimitHit(limiterType, identifier string) {
	m.RateLimitHits.WithLabelValues(limiterType, identifier).Inc()
}

// RecordRateLimitBlock records a rate limit block
func (m *Metrics) RecordRateLimitBlock(limiterType, identifier string) {
	m.RateLimitBlocks.WithLabelValues(limiterType, identifier).Inc()
}

// RecordHTTPRequest records an HTTP request
func (m *Metrics) RecordHTTPRequest(method, endpoint, statusCode string, duration time.Duration, requestSize, responseSize int64) {
	m.HTTPRequests.WithLabelValues(method, endpoint, statusCode).Inc()
	m.HTTPDuration.WithLabelValues(method, endpoint, statusCode).Observe(duration.Seconds())
	m.HTTPRequestSize.WithLabelValues(method, endpoint).Observe(float64(requestSize))
	m.HTTPResponseSize.WithLabelValues(method, endpoint, statusCode).Observe(float64(responseSize))
}

// RecordGRPCRequest records a gRPC request
func (m *Metrics) RecordGRPCRequest(service, method, statusCode string, duration time.Duration) {
	m.GRPCRequests.WithLabelValues(service, method, statusCode).Inc()
	m.GRPCDuration.WithLabelValues(service, method, statusCode).Observe(duration.Seconds())
}

// SetActiveSessions sets the number of active sessions
func (m *Metrics) SetActiveSessions(sessionType string, count int) {
	m.ActiveSessions.WithLabelValues(sessionType).Set(float64(count))
}

// SetSystemHealth sets the system health status
func (m *Metrics) SetSystemHealth(component string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	m.SystemHealth.WithLabelValues(component).Set(value)
}

// Handler returns an HTTP handler for Prometheus metrics
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// MetricsCollector provides methods to collect and update metrics
type MetricsCollector struct {
	metrics *Metrics
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(metrics *Metrics) *MetricsCollector {
	return &MetricsCollector{
		metrics: metrics,
	}
}

// CollectSystemMetrics collects system-wide metrics
func (c *MetricsCollector) CollectSystemMetrics(ctx context.Context) error {
	// This would typically collect metrics from various system components
	// For now, we'll set some basic health indicators
	c.metrics.SetSystemHealth("application", true)
	return nil
}

// StartPeriodicCollection starts periodic collection of system metrics
func (c *MetricsCollector) StartPeriodicCollection(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.CollectSystemMetrics(ctx); err != nil {
				// Log error but continue collection
				continue
			}
		}
	}
}
