package monitoring

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.AuthAttempts)
	assert.NotNil(t, metrics.AuthSuccesses)
	assert.NotNil(t, metrics.AuthFailures)
	assert.NotNil(t, metrics.DatabaseQueries)
	assert.NotNil(t, metrics.CacheHits)
	assert.NotNil(t, metrics.HTTPRequests)
}

func TestMetrics_RecordAuthAttempt(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	// Record some auth attempts
	metrics.RecordAuthAttempt("password", "success")
	metrics.RecordAuthAttempt("password", "failure")
	metrics.RecordAuthAttempt("oauth", "success")

	// Check that metrics were recorded
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthAttempts.WithLabelValues("password", "success")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthAttempts.WithLabelValues("password", "failure")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthAttempts.WithLabelValues("oauth", "success")))
}

func TestMetrics_RecordAuthSuccess(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordAuthSuccess("password", "regular")
	metrics.RecordAuthSuccess("oauth", "admin")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthSuccesses.WithLabelValues("password", "regular")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthSuccesses.WithLabelValues("oauth", "admin")))
}

func TestMetrics_RecordAuthFailure(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordAuthFailure("password", "invalid_password")
	metrics.RecordAuthFailure("password", "user_not_found")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthFailures.WithLabelValues("password", "invalid_password")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.AuthFailures.WithLabelValues("password", "user_not_found")))
}

func TestMetrics_RecordAuthDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 100 * time.Millisecond
	metrics.RecordAuthDuration("password", "success", duration)

	// TODO:
	// Check that histogram was updated
	// histogram := metrics.AuthDuration.WithLabelValues("password", "success")
	// assert.Greater(t, testutil.ToFloat64(histogram), 0.0)
}

func TestMetrics_RecordTokenGeneration(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordTokenGeneration("jwt")
	metrics.RecordTokenGeneration("paseto")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.TokenGenerations.WithLabelValues("jwt")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.TokenGenerations.WithLabelValues("paseto")))
}

func TestMetrics_RecordTokenValidation(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordTokenValidation("jwt", "success")
	metrics.RecordTokenValidation("jwt", "failure")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.TokenValidations.WithLabelValues("jwt", "success")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.TokenValidations.WithLabelValues("jwt", "failure")))
}

func TestMetrics_RecordUserRegistration(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordUserRegistration("direct")
	metrics.RecordUserRegistration("oauth")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.UserRegistrations.WithLabelValues("direct")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.UserRegistrations.WithLabelValues("oauth")))
}

func TestMetrics_RecordDatabaseConnections(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordDatabaseConnections(5, 3, 10)

	assert.Equal(t, 5.0, testutil.ToFloat64(metrics.DatabaseConnections.WithLabelValues("active")))
	assert.Equal(t, 3.0, testutil.ToFloat64(metrics.DatabaseConnections.WithLabelValues("idle")))
	assert.Equal(t, 10.0, testutil.ToFloat64(metrics.DatabaseConnections.WithLabelValues("max")))
}

func TestMetrics_RecordDatabaseQuery(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 50 * time.Millisecond
	metrics.RecordDatabaseQuery("SELECT", "users", duration)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.DatabaseQueries.WithLabelValues("SELECT", "users")))

	// TODO:
	// histogram := metrics.DatabaseQueryDuration.WithLabelValues("SELECT", "users")
	// assert.Greater(t, testutil.ToFloat64(histogram), 0.0)
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordCacheHit("redis", "get")
	metrics.RecordCacheMiss("redis", "get")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.CacheHits.WithLabelValues("redis", "get")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.CacheMisses.WithLabelValues("redis", "get")))
}

func TestMetrics_RecordCacheOperation(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 10 * time.Millisecond
	metrics.RecordCacheOperation("redis", "set", "success", duration)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.CacheOperations.WithLabelValues("redis", "set", "success")))

	// TODO:
	// histogram := metrics.CacheOperationDuration.WithLabelValues("redis", "set")
	// assert.Greater(t, testutil.ToFloat64(histogram), 0.0)
}

func TestMetrics_RecordHTTPRequest(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 200 * time.Millisecond
	metrics.RecordHTTPRequest("GET", "/api/users", "200", duration, 1024, 2048)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.HTTPRequests.WithLabelValues("GET", "/api/users", "200")))

	// TODO:
	// durationHistogram := metrics.HTTPDuration.WithLabelValues("GET", "/api/users", "200")
	// assert.Greater(t, testutil.ToFloat64(durationHistogram), 0.0)

	// requestSizeHistogram := metrics.HTTPRequestSize.WithLabelValues("GET", "/api/users")
	// assert.Greater(t, testutil.ToFloat64(requestSizeHistogram), 0.0)

	// responseSizeHistogram := metrics.HTTPResponseSize.WithLabelValues("GET", "/api/users", "200")
	// assert.Greater(t, testutil.ToFloat64(responseSizeHistogram), 0.0)
}

func TestMetrics_RecordGRPCRequest(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 150 * time.Millisecond
	metrics.RecordGRPCRequest("AuthService", "Login", "OK", duration)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.GRPCRequests.WithLabelValues("AuthService", "Login", "OK")))

	// TODO:
	// histogram := metrics.GRPCDuration.WithLabelValues("AuthService", "Login", "OK")
	// assert.Greater(t, testutil.ToFloat64(histogram), 0.0)
}

func TestMetrics_SetActiveSessions(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.SetActiveSessions("web", 100)
	metrics.SetActiveSessions("mobile", 50)

	assert.Equal(t, 100.0, testutil.ToFloat64(metrics.ActiveSessions.WithLabelValues("web")))
	assert.Equal(t, 50.0, testutil.ToFloat64(metrics.ActiveSessions.WithLabelValues("mobile")))
}

func TestMetrics_SetSystemHealth(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.SetSystemHealth("database", true)
	metrics.SetSystemHealth("cache", false)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.SystemHealth.WithLabelValues("database")))
	assert.Equal(t, 0.0, testutil.ToFloat64(metrics.SystemHealth.WithLabelValues("cache")))
}

func TestMetrics_RecordMFAAttempt(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordMFAAttempt("totp")
	metrics.RecordMFASuccess("totp")
	metrics.RecordMFAFailure("sms", "invalid_code")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.MFAAttempts.WithLabelValues("totp")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.MFASuccesses.WithLabelValues("totp")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.MFAFailures.WithLabelValues("sms", "invalid_code")))
}

func TestMetrics_RecordRateLimit(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	metrics.RecordRateLimitHit("ip", "192.168.1.1")
	metrics.RecordRateLimitBlock("user", "user123")

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.RateLimitHits.WithLabelValues("ip", "192.168.1.1")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.RateLimitBlocks.WithLabelValues("user", "user123")))
}

func TestMetricsCollector_CollectSystemMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	collector := NewMetricsCollector(metrics)

	err := collector.CollectSystemMetrics(nil)
	assert.NoError(t, err)

	// Check that system health was set
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.SystemHealth.WithLabelValues("application")))
}

func TestMetrics_Handler(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	handler := metrics.Handler()
	assert.NotNil(t, handler)
}

func BenchmarkMetrics_RecordAuthAttempt(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordAuthAttempt("password", "success")
	}
}

func BenchmarkMetrics_RecordHTTPRequest(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 100 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordHTTPRequest("GET", "/api/users", "200", duration, 1024, 2048)
	}
}

func BenchmarkMetrics_RecordDatabaseQuery(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	duration := 50 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordDatabaseQuery("SELECT", "users", duration)
	}
}
