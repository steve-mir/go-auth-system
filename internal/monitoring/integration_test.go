package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMonitoringIntegration(t *testing.T) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Prometheus: PrometheusConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    9090,
		},
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)
	require.NotNil(t, service)

	// Test that all components are initialized
	assert.NotNil(t, service.GetMetrics())
	assert.NotNil(t, service.GetLogger())
	assert.NotNil(t, service.GetRegistry())

	// Test health check
	ctx := context.Background()
	err = service.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestHTTPMiddlewareIntegration(t *testing.T) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Set up Gin router with monitoring middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(service.HTTPMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	router.POST("/error", func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "test error"})
	})

	// Test successful request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Test error request
	req = httptest.NewRequest("POST", "/error", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Verify metrics were recorded
	metrics := service.GetMetrics()
	assert.Greater(t, testutil.ToFloat64(metrics.HTTPRequests.WithLabelValues("GET", "/test", "200")), 0.0)
	assert.Greater(t, testutil.ToFloat64(metrics.HTTPRequests.WithLabelValues("POST", "/error", "500")), 0.0)
}

func TestMetricsEndpoint(t *testing.T) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Prometheus: PrometheusConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    9090,
		},
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Record some metrics
	ctx := context.Background()
	service.RecordAuthEvent(ctx, "password", "user123", true, 100*time.Millisecond, map[string]interface{}{})
	service.RecordTokenEvent(ctx, "generate", "jwt", true, map[string]interface{}{})
	service.UpdateSystemHealth("test", true)

	// Test metrics handler
	handler := service.MetricsHandler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")

	// Check that metrics are present in the response
	body := w.Body.String()
	assert.Contains(t, body, "auth_attempts_total")
	assert.Contains(t, body, "token_generations_total")
	assert.Contains(t, body, "system_health")
}

func TestEndToEndMonitoring(t *testing.T) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Prometheus: PrometheusConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    9090,
		},
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Set up a complete HTTP server with monitoring
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add all monitoring middleware
	router.Use(RequestIDMiddleware())
	router.Use(TraceIDMiddleware())
	router.Use(service.HTTPMiddleware())

	// Add endpoints
	router.POST("/api/auth/login", func(c *gin.Context) {
		start := time.Now()

		// Simulate authentication
		userID := "user123"
		method := "password"
		success := true

		details := map[string]interface{}{
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		}

		service.RecordAuthEvent(
			c.Request.Context(),
			method,
			userID,
			success,
			time.Since(start),
			details,
		)

		c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
	})

	router.GET("/metrics", gin.WrapH(service.MetricsHandler()))

	// Test login endpoint
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"test","password":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	assert.NotEmpty(t, w.Header().Get("X-Trace-ID"))

	// Test metrics endpoint
	req = httptest.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "auth_attempts_total")
	assert.Contains(t, body, "auth_successes_total")
	assert.Contains(t, body, "http_requests_total")
}

func TestMiddlewareChaining(t *testing.T) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Test database middleware
	dbMiddleware := service.DatabaseMiddleware()

	executed := false
	err = dbMiddleware("SELECT", "users", func() error {
		executed = true
		time.Sleep(10 * time.Millisecond)
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, executed)

	// Test cache middleware
	cacheMiddleware := service.CacheMiddleware()
	ctx := context.Background()

	hit, err := cacheMiddleware(ctx, "redis", "get", "test:key", func() (bool, error) {
		return true, nil
	})

	assert.NoError(t, err)
	assert.True(t, hit)

	// Test auth middleware
	authMiddleware := service.AuthMiddleware()

	err = authMiddleware(ctx, "password", "user123", func() error {
		time.Sleep(5 * time.Millisecond)
		return nil
	})

	assert.NoError(t, err)

	// Verify metrics were recorded
	metrics := service.GetMetrics()
	assert.Greater(t, testutil.ToFloat64(metrics.DatabaseQueries.WithLabelValues("SELECT", "users")), 0.0)
	assert.Greater(t, testutil.ToFloat64(metrics.CacheHits.WithLabelValues("redis", "get")), 0.0)
	assert.Greater(t, testutil.ToFloat64(metrics.AuthSuccesses.WithLabelValues("password", "user")), 0.0)
}

func TestMetricsCollection(t *testing.T) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Start collection with short interval for testing
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	service.StartCollection(ctx, 50*time.Millisecond)

	// Wait for collection to run
	<-ctx.Done()

	// Verify system health metric was set
	metrics := service.GetMetrics()
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.SystemHealth.WithLabelValues("application")))
}

func TestDisabledMonitoring(t *testing.T) {
	// Create disabled monitoring service
	config := Config{
		Enabled: false,
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Test that operations don't panic with disabled service
	ctx := context.Background()

	service.RecordAuthEvent(ctx, "password", "user123", true, 100*time.Millisecond, map[string]interface{}{})
	service.RecordTokenEvent(ctx, "generate", "jwt", true, map[string]interface{}{})
	service.UpdateSystemHealth("test", true)

	err = service.HealthCheck(ctx)
	assert.NoError(t, err)

	handler := service.MetricsHandler()
	assert.NotNil(t, handler)

	err = service.Close()
	assert.NoError(t, err)
}

func TestCustomRegistry(t *testing.T) {
	// Create custom registry
	registry := prometheus.NewRegistry()

	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	// Verify registry is set
	assert.NotNil(t, service.GetRegistry())

	// Record some metrics
	ctx := context.Background()
	service.RecordAuthEvent(ctx, "password", "user123", true, 100*time.Millisecond, map[string]interface{}{})

	// Verify metrics are registered
	metrics := service.GetMetrics()
	assert.Greater(t, testutil.ToFloat64(metrics.AuthSuccesses.WithLabelValues("password", "user")), 0.0)
}

func BenchmarkMonitoringOverhead(b *testing.B) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelError, // Reduce logging for benchmark
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(b, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"ip": "192.168.1.1",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			service.RecordAuthEvent(ctx, "password", "user123", true, 100*time.Millisecond, details)
		}
	})
}

func BenchmarkHTTPMiddleware(b *testing.B) {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelError, // Reduce logging for benchmark
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(b, err)

	// Set up router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(service.HTTPMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
