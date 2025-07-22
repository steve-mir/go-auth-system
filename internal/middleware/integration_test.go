package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareIntegration_FullStack(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	// Configure middleware with low limits for testing
	config := DefaultConfig()
	config.RateLimit.GlobalLimit = 5
	config.RateLimit.IPLimit = 3
	config.RateLimit.UserLimit = 2
	config.Security.BlockedUserAgents = []string{"bot"}
	config.Security.MaxLoginAttemptsPerIP = 2
	config.Security.BlockSuspiciousRequests = true

	manager := NewMiddlewareManager(config, redisClient)
	authMW := NewAuthenticationMiddleware()
	metricsMW := NewMetricsMiddleware()

	// Set up router with full middleware stack
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(CORSMiddleware())
	router.Use(HealthCheckMiddleware())
	router.Use(RecoveryMiddleware())
	router.Use(metricsMW.Handler())
	router.Use(manager.CombinedSecurityHandler())

	// Public endpoints
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"token": "dummy-token", "user_id": "user123"})
	})

	// Protected endpoints
	protected := router.Group("/api/v1")
	protected.Use(authMW.Handler())
	protected.GET("/profile", func(c *gin.Context) {
		userID := c.GetString("user_id")
		c.JSON(200, gin.H{"user_id": userID, "profile": "data"})
	})

	t.Run("Health Check Bypasses All Middleware", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "healthy")
	})

	t.Run("CORS Headers Are Set", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/auth/login", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("Request ID Is Generated", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("Blocked User Agent Is Rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.Header.Set("User-Agent", "TestBot/1.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "access denied")
	})

	t.Run("Rate Limiting Works", func(t *testing.T) {
		clientIP := "203.0.113.100"

		// Make requests up to the IP limit
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
			req.Header.Set("X-Real-IP", clientIP)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-IP-Limit"))
		}

		// Next request should be rate limited
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "rate limit exceeded")
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
	})

	t.Run("Authentication Required for Protected Endpoints", func(t *testing.T) {
		// Request without auth header
		req := httptest.NewRequest("GET", "/api/v1/profile", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "missing authorization header")

		// Request with valid auth header
		req = httptest.NewRequest("GET", "/api/v1/profile", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w = httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "dummy-user-id")
	})

	t.Run("Metrics Are Collected", func(t *testing.T) {
		initialMetrics := metricsMW.GetMetrics()

		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.Header.Set("X-Real-IP", "203.0.113.200") // Different IP to avoid rate limiting
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		finalMetrics := metricsMW.GetMetrics()
		assert.Greater(t, finalMetrics["POST /api/v1/auth/login"], initialMetrics["POST /api/v1/auth/login"])
	})

	t.Run("Panic Recovery Works", func(t *testing.T) {
		// Add a route that panics
		router.GET("/panic", func(c *gin.Context) {
			panic("test panic")
		})

		req := httptest.NewRequest("GET", "/panic", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "internal server error")
		assert.Contains(t, w.Body.String(), "request_id")
	})
}

func TestMiddlewareIntegration_SuspiciousActivityDetection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	config.Security.MaxLoginAttemptsPerIP = 3
	config.Security.LogSuspiciousActivity = true
	config.Security.BlockSuspiciousRequests = false // Don't block for this test

	manager := NewMiddlewareManager(config, redisClient)

	router := gin.New()
	router.Use(manager.SecurityHandler())
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "login attempt"})
	})

	clientIP := "203.0.113.50"

	// Make multiple login attempts to trigger suspicious activity detection
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// All should succeed since we're not blocking
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Check that suspicious activities were logged
	ctx := context.Background()
	activities, err := manager.GetSecurityMiddleware().GetSuspiciousActivities(ctx, 10)
	require.NoError(t, err)

	// Should have detected rapid login attempts
	found := false
	for _, activity := range activities {
		if activity.Type == "rapid_login_attempts" || activity.Type == "elevated_login_attempts" {
			found = true
			assert.Equal(t, clientIP, activity.IP)
			break
		}
	}
	assert.True(t, found, "Should have detected suspicious login activity")
}

func TestMiddlewareIntegration_AccountLockout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	config.RateLimit.MaxFailedAttempts = 2
	config.RateLimit.LockoutDuration = time.Hour

	manager := NewMiddlewareManager(config, redisClient)
	ctx := context.Background()

	userEmail := "test@example.com"

	// Record failed login attempts
	rateLimitMW := manager.GetRateLimitMiddleware()

	// First attempt should not lock
	result, err := rateLimitMW.RecordFailedLogin(ctx, userEmail)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 1, result.Attempts)

	// Second attempt should lock
	result, err = rateLimitMW.RecordFailedLogin(ctx, userEmail)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, 2, result.Attempts)
	assert.False(t, result.Until.IsZero())

	// Check if account is locked
	lockStatus, err := rateLimitMW.IsAccountLocked(ctx, userEmail)
	require.NoError(t, err)
	assert.True(t, lockStatus.Blocked)
	assert.Equal(t, 2, lockStatus.Attempts)

	// Clear failed attempts (simulate successful login)
	err = rateLimitMW.ClearFailedAttempts(ctx, userEmail)
	require.NoError(t, err)

	// Account should no longer be locked
	lockStatus, err = rateLimitMW.IsAccountLocked(ctx, userEmail)
	require.NoError(t, err)
	assert.False(t, lockStatus.Blocked)
	assert.Equal(t, 0, lockStatus.Attempts)
}

func TestMiddlewareIntegration_DeviceFingerprinting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	config.Security.EnableDeviceFingerprinting = true
	config.Security.MaxDevicesPerUser = 2
	config.Security.LogSuspiciousActivity = true
	config.Security.BlockSuspiciousRequests = false

	manager := NewMiddlewareManager(config, redisClient)

	router := gin.New()
	router.Use(manager.SecurityHandler())
	router.GET("/api/v1/profile", func(c *gin.Context) {
		c.Set("user_id", "user123") // Simulate authenticated user
		c.JSON(200, gin.H{"profile": "data"})
	})

	// Make requests with different device fingerprints
	devices := []map[string]string{
		{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate",
		},
		{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.8",
			"Accept-Encoding": "gzip, deflate, br",
		},
		{
			"User-Agent":      "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.7",
			"Accept-Encoding": "gzip, deflate",
		},
	}

	for i, device := range devices {
		req := httptest.NewRequest("GET", "/api/v1/profile", nil)
		for header, value := range device {
			req.Header.Set(header, value)
		}
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
	}

	// Check for device anomaly detection
	ctx := context.Background()
	activities, err := manager.GetSecurityMiddleware().GetSuspiciousActivities(ctx, 10)
	require.NoError(t, err)

	// Should have detected too many devices
	found := false
	for _, activity := range activities {
		if activity.Type == "too_many_devices" {
			found = true
			assert.Equal(t, "user123", activity.UserID)
			break
		}
	}
	assert.True(t, found, "Should have detected too many devices")
}

func TestMiddlewareIntegration_MultipleUserAttempts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	config.Security.MaxDifferentUsersPerIP = 2
	config.Security.LogSuspiciousActivity = true
	config.Security.BlockSuspiciousRequests = false

	manager := NewMiddlewareManager(config, redisClient)

	router := gin.New()
	router.Use(manager.SecurityHandler())
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "login attempt"})
	})

	clientIP := "203.0.113.75"
	users := []string{"user1", "user2", "user3"}

	// Attempt to login as different users from same IP
	for _, user := range users {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.PostForm = map[string][]string{
			"username": {user},
		}
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Check for multiple user attempts detection
	ctx := context.Background()
	activities, err := manager.GetSecurityMiddleware().GetSuspiciousActivities(ctx, 10)
	require.NoError(t, err)

	// Should have detected multiple user attempts
	found := false
	for _, activity := range activities {
		if activity.Type == "multiple_user_attempts" {
			found = true
			assert.Equal(t, clientIP, activity.IP)
			break
		}
	}
	assert.True(t, found, "Should have detected multiple user attempts")
}

func TestMiddlewareIntegration_HeadersAndMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultConfig()
	config.RateLimit.IncludeHeaders = true

	manager := NewMiddlewareManager(config, redisClient)

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(manager.RateLimitHandler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"request_id": c.GetString("request_id"),
			"status":     "ok",
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-request-123")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that all expected headers are present
	assert.Equal(t, "test-request-123", w.Header().Get("X-Request-ID"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Global-Limit"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Global-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Global-Reset"))

	// Check response contains request ID
	assert.Contains(t, w.Body.String(), "test-request-123")
}
