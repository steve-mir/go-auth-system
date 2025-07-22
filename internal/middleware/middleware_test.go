package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.NotNil(t, config.RateLimit)
	assert.NotNil(t, config.Security)

	// Verify rate limit defaults
	assert.Equal(t, int64(1000), config.RateLimit.GlobalLimit)
	assert.Equal(t, time.Hour, config.RateLimit.GlobalWindow)

	// Verify security defaults
	assert.Equal(t, 20, config.Security.MaxLoginAttemptsPerIP)
	assert.Equal(t, time.Hour, config.Security.MaxLoginAttemptsWindow)
}

func TestNewMiddlewareManager(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	manager := NewMiddlewareManager(config, redisClient)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.rateLimitMiddleware)
	assert.NotNil(t, manager.securityMiddleware)
	assert.Equal(t, config, manager.config)
}

func TestMiddlewareManager_Handlers(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	manager := NewMiddlewareManager(config, redisClient)

	// Test that handlers are not nil
	assert.NotNil(t, manager.RateLimitHandler())
	assert.NotNil(t, manager.SecurityHandler())
	assert.NotNil(t, manager.CombinedSecurityHandler())
}

func TestMiddlewareManager_GetMiddleware(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	manager := NewMiddlewareManager(config, redisClient)

	rateLimitMW := manager.GetRateLimitMiddleware()
	securityMW := manager.GetSecurityMiddleware()

	assert.NotNil(t, rateLimitMW)
	assert.NotNil(t, securityMW)
	assert.Equal(t, manager.rateLimitMiddleware, rateLimitMW)
	assert.Equal(t, manager.securityMiddleware, securityMW)
}

func TestMiddlewareManager_CombinedSecurityHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	// Set blocked IP for testing
	config.Security.BlockedIPs = []string{"192.168.1.100"}
	config.Security.BlockSuspiciousRequests = true

	manager := NewMiddlewareManager(config, redisClient)

	router := gin.New()
	router.Use(manager.CombinedSecurityHandler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Test blocked request (should be blocked by security middleware)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")

	// Test allowed request
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
}

func TestAuthenticationMiddleware_Handler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authMW := NewAuthenticationMiddleware()

	router := gin.New()
	router.Use(authMW.Handler())
	router.GET("/protected", func(c *gin.Context) {
		userID := c.GetString("user_id")
		c.JSON(200, gin.H{"user_id": userID})
	})

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectUserID   bool
	}{
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectUserID:   false,
		},
		{
			name:           "invalid authorization header format",
			authHeader:     "InvalidFormat token123",
			expectedStatus: http.StatusUnauthorized,
			expectUserID:   false,
		},
		{
			name:           "missing token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectUserID:   false,
		},
		{
			name:           "valid authorization header",
			authHeader:     "Bearer valid-token-123",
			expectedStatus: http.StatusOK,
			expectUserID:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectUserID {
				assert.Contains(t, w.Body.String(), "dummy-user-id")
			}
		})
	}
}

func TestCORSMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CORSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Test regular request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Headers"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))

	// Test OPTIONS request
	req = httptest.NewRequest("OPTIONS", "/test", nil)
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.GET("/test", func(c *gin.Context) {
		requestID := c.GetString("request_id")
		c.JSON(200, gin.H{"request_id": requestID})
	})

	// Test without existing request ID
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	assert.Contains(t, w.Body.String(), "request_id")

	// Test with existing request ID
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "existing-request-id")
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "existing-request-id", w.Header().Get("X-Request-ID"))
	assert.Contains(t, w.Body.String(), "existing-request-id")
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2) // Should be different (though not guaranteed due to timing)
	assert.Contains(t, id1, "-req")
	assert.Contains(t, id2, "-req")
}

func TestHealthCheckMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(HealthCheckMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "test"})
	})

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectHealth   bool
	}{
		{
			name:           "health endpoint",
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectHealth:   true,
		},
		{
			name:           "healthz endpoint",
			path:           "/healthz",
			expectedStatus: http.StatusOK,
			expectHealth:   true,
		},
		{
			name:           "regular endpoint",
			path:           "/test",
			expectedStatus: http.StatusOK,
			expectHealth:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectHealth {
				assert.Contains(t, w.Body.String(), "healthy")
				assert.Contains(t, w.Body.String(), "timestamp")
			} else {
				assert.Contains(t, w.Body.String(), "test")
			}
		})
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestIDMiddleware()) // Add request ID for testing
	router.Use(RecoveryMiddleware())
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Test panic recovery
	req := httptest.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal server error")
	assert.Contains(t, w.Body.String(), "request_id")

	// Test normal request
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
}

func TestMetricsMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	metricsMW := NewMetricsMiddleware()

	router := gin.New()
	router.Use(metricsMW.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Make some requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Check metrics
	metrics := metricsMW.GetMetrics()
	assert.Equal(t, int64(3), metrics["GET /test"])
}

func TestMetricsMiddleware_SlowRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	metricsMW := NewMetricsMiddleware()

	router := gin.New()
	router.Use(metricsMW.Handler())
	router.GET("/slow", func(c *gin.Context) {
		time.Sleep(1100 * time.Millisecond) // Simulate slow request
		c.JSON(200, gin.H{"status": "slow"})
	})

	req := httptest.NewRequest("GET", "/slow", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that the request was recorded
	metrics := metricsMW.GetMetrics()
	assert.Equal(t, int64(1), metrics["GET /slow"])
}
