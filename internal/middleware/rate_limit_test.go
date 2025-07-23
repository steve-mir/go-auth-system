package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRedisClient(t *testing.T) *redis.Client {
	client, err := redis.NewClient(&config.RedisConfig{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       1, // Use test database
	})
	require.NoError(t, err)

	// Clean up test data
	client.FlushDB(context.Background())

	return client
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	assert.Equal(t, int64(1000), config.GlobalLimit)
	assert.Equal(t, time.Hour, config.GlobalWindow)
	assert.Equal(t, int64(100), config.IPLimit)
	assert.Equal(t, time.Hour, config.IPWindow)
	assert.Equal(t, int64(200), config.UserLimit)
	assert.Equal(t, time.Hour, config.UserWindow)
	assert.Equal(t, 5, config.MaxFailedAttempts)
	assert.Equal(t, time.Hour, config.LockoutDuration)
	assert.True(t, config.IncludeHeaders)
	assert.Contains(t, config.SkipPaths, "/health")
	assert.Contains(t, config.SkipPaths, "/metrics")
}

func TestNewRateLimitMiddleware(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	middleware := NewRateLimitMiddleware(config, redisClient)

	assert.NotNil(t, middleware)
	assert.Equal(t, config, middleware.config)
	assert.NotNil(t, middleware.globalLimiter)
	assert.NotNil(t, middleware.ipLimiter)
	assert.NotNil(t, middleware.userLimiter)
	assert.NotNil(t, middleware.accountLockout)
}

func TestRateLimitMiddleware_ShouldSkipPath(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	middleware := NewRateLimitMiddleware(config, redisClient)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "health endpoint should be skipped",
			path:     "/health",
			expected: true,
		},
		{
			name:     "metrics endpoint should be skipped",
			path:     "/metrics",
			expected: true,
		},
		{
			name:     "health subpath should be skipped",
			path:     "/health/check",
			expected: true,
		},
		{
			name:     "api endpoint should not be skipped",
			path:     "/api/v1/auth/login",
			expected: false,
		},
		{
			name:     "root path should not be skipped",
			path:     "/",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.shouldSkipPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRateLimitMiddleware_GetClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:          "X-Forwarded-For header",
			remoteAddr:    "192.168.1.1:8080",
			xForwardedFor: "203.0.113.1, 192.168.1.1",
			expectedIP:    "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "192.168.1.1:8080",
			xRealIP:    "203.0.113.2",
			expectedIP: "203.0.113.2",
		},
		{
			name:       "RemoteAddr fallback",
			remoteAddr: "203.0.113.3:8080",
			expectedIP: "203.0.113.3",
		},
		{
			name:          "Invalid X-Forwarded-For falls back to RemoteAddr",
			remoteAddr:    "203.0.113.4:8080",
			xForwardedFor: "invalid-ip",
			expectedIP:    "203.0.113.4",
		},
	}

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	middleware := NewRateLimitMiddleware(config, redisClient)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			c.Request = req

			ip := middleware.getClientIP(c)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestRateLimitMiddleware_GetUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	middleware := NewRateLimitMiddleware(config, redisClient)

	tests := []struct {
		name       string
		setupFunc  func(*gin.Context)
		expectedID string
	}{
		{
			name: "user_id in context",
			setupFunc: func(c *gin.Context) {
				c.Set("user_id", "user123")
			},
			expectedID: "user123",
		},
		{
			name: "user_id in claims",
			setupFunc: func(c *gin.Context) {
				c.Set("claims", map[string]interface{}{
					"user_id": "user456",
				})
			},
			expectedID: "user456",
		},
		{
			name:       "no user_id available",
			setupFunc:  func(c *gin.Context) {},
			expectedID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			tt.setupFunc(c)

			userID := middleware.getUserID(c)
			assert.Equal(t, tt.expectedID, userID)
		})
	}
}

func TestRateLimitMiddleware_Handler_SkipPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	middleware := NewRateLimitMiddleware(config, redisClient)

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
}

func TestRateLimitMiddleware_Handler_GlobalLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.GlobalLimit = 2 // Set low limit for testing
	middleware := NewRateLimitMiddleware(config, redisClient)

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)

		// Check rate limit headers
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Global-Limit"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Global-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Global-Reset"))
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "global rate limit exceeded")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestRateLimitMiddleware_Handler_IPLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.GlobalLimit = 1000 // High global limit
	config.IPLimit = 2        // Low IP limit for testing
	middleware := NewRateLimitMiddleware(config, redisClient)

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	clientIP := "203.0.113.1"

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", clientIP)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)

		// Check rate limit headers
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-IP-Limit"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-IP-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-IP-Reset"))
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", clientIP)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "IP rate limit exceeded")
}

func TestRateLimitMiddleware_Handler_UserLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.GlobalLimit = 1000 // High global limit
	config.IPLimit = 1000     // High IP limit
	config.UserLimit = 2      // Low user limit for testing
	middleware := NewRateLimitMiddleware(config, redisClient)

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", "user123") // Set user ID in context
		c.JSON(200, gin.H{"status": "ok"})
	})

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)

		// Check rate limit headers
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-User-Limit"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-User-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-User-Reset"))
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "user rate limit exceeded")
}

func TestRateLimitMiddleware_RecordFailedLogin(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.MaxFailedAttempts = 3
	config.LockoutDuration = time.Hour
	middleware := NewRateLimitMiddleware(config, redisClient)

	ctx := context.Background()
	identifier := "user@example.com"

	// First two attempts should not lock
	for i := 0; i < 2; i++ {
		result, err := middleware.RecordFailedLogin(ctx, identifier)
		require.NoError(t, err)
		assert.False(t, result.Blocked, "Attempt %d should not be blocked", i+1)
		assert.Equal(t, i+1, result.Attempts)
	}

	// Third attempt should lock
	result, err := middleware.RecordFailedLogin(ctx, identifier)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, 3, result.Attempts)
	assert.False(t, result.Until.IsZero())
	assert.Equal(t, "too many failed attempts", result.Reason)
}

func TestRateLimitMiddleware_IsAccountLocked(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.MaxFailedAttempts = 2
	config.LockoutDuration = time.Hour
	middleware := NewRateLimitMiddleware(config, redisClient)

	ctx := context.Background()
	identifier := "user@example.com"

	// Initially not locked
	result, err := middleware.IsAccountLocked(ctx, identifier)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 0, result.Attempts)

	// Lock the account
	_, err = middleware.RecordFailedLogin(ctx, identifier)
	require.NoError(t, err)
	_, err = middleware.RecordFailedLogin(ctx, identifier)
	require.NoError(t, err)

	// Should now be locked
	result, err = middleware.IsAccountLocked(ctx, identifier)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, 2, result.Attempts)
	assert.False(t, result.Until.IsZero())
}

func TestRateLimitMiddleware_ClearFailedAttempts(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.MaxFailedAttempts = 5
	middleware := NewRateLimitMiddleware(config, redisClient)

	ctx := context.Background()
	identifier := "user@example.com"

	// Record some failed attempts
	for i := 0; i < 3; i++ {
		_, err := middleware.RecordFailedLogin(ctx, identifier)
		require.NoError(t, err)
	}

	// Verify attempts are recorded
	result, err := middleware.IsAccountLocked(ctx, identifier)
	require.NoError(t, err)
	assert.Equal(t, 3, result.Attempts)

	// Clear attempts
	err = middleware.ClearFailedAttempts(ctx, identifier)
	require.NoError(t, err)

	// Verify attempts are cleared
	result, err = middleware.IsAccountLocked(ctx, identifier)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Attempts)
	assert.False(t, result.Blocked)
}

func TestRateLimitMiddleware_UnlockAccount(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	config.MaxFailedAttempts = 1
	config.LockoutDuration = time.Hour
	middleware := NewRateLimitMiddleware(config, redisClient)

	ctx := context.Background()
	identifier := "user@example.com"

	// Lock the account
	_, err := middleware.RecordFailedLogin(ctx, identifier)
	require.NoError(t, err)

	// Verify it's locked
	result, err := middleware.IsAccountLocked(ctx, identifier)
	require.NoError(t, err)
	assert.True(t, result.Blocked)

	// Unlock the account
	err = middleware.UnlockAccount(ctx, identifier)
	require.NoError(t, err)

	// Verify it's unlocked
	result, err = middleware.IsAccountLocked(ctx, identifier)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 0, result.Attempts)
}

func TestRateLimitMiddleware_SetRateLimitHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultRateLimitConfig()
	middleware := NewRateLimitMiddleware(config, redisClient)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	result := &redis.RateLimitResult{
		Allowed:   true,
		Count:     5,
		Limit:     10,
		Remaining: 5,
		ResetTime: time.Now().Add(time.Hour),
	}

	middleware.setRateLimitHeaders(c, result, "Test")

	assert.Equal(t, "10", w.Header().Get("X-RateLimit-Test-Limit"))
	assert.Equal(t, "5", w.Header().Get("X-RateLimit-Test-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Test-Reset"))
	assert.Empty(t, w.Header().Get("Retry-After")) // Should be empty when allowed

	// Test with not allowed
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)

	result.Allowed = false
	result.RetryAfter = 30 * time.Second

	middleware.setRateLimitHeaders(c, result, "Test")

	assert.Equal(t, "30", w.Header().Get("Retry-After"))
}
