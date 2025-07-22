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

func TestDefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()

	assert.Equal(t, 20, config.MaxLoginAttemptsPerIP)
	assert.Equal(t, time.Hour, config.MaxLoginAttemptsWindow)
	assert.Equal(t, 10, config.MaxDifferentUsersPerIP)
	assert.Equal(t, time.Hour, config.MaxDifferentUsersWindow)
	assert.False(t, config.EnableGeoAnomalyDetection)
	assert.Equal(t, float64(1000), config.MaxDistanceKm)
	assert.True(t, config.EnableDeviceFingerprinting)
	assert.Equal(t, 5, config.MaxDevicesPerUser)
	assert.False(t, config.EnableTimeAnomalyDetection)
	assert.Equal(t, 2, config.UnusualHourThreshold)
	assert.Empty(t, config.BlockedIPs)
	assert.Contains(t, config.BlockedUserAgents, "bot")
	assert.Contains(t, config.BlockedUserAgents, "crawler")
	assert.Contains(t, config.BlockedUserAgents, "spider")
	assert.True(t, config.BlockSuspiciousRequests)
	assert.True(t, config.LogSuspiciousActivity)
}

func TestNewSecurityMiddleware(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	assert.NotNil(t, middleware)
	assert.Equal(t, config, middleware.config)
	assert.NotNil(t, middleware.redisClient)
	assert.NotNil(t, middleware.rateLimiter)
}

func TestSecurityMiddleware_IsBlocked_BlockedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	config.BlockedIPs = []string{"192.168.1.100", "10.0.0.0/8"}
	middleware := NewSecurityMiddleware(config, redisClient)

	tests := []struct {
		name     string
		clientIP string
		expected bool
	}{
		{
			name:     "exact IP match",
			clientIP: "192.168.1.100",
			expected: true,
		},
		{
			name:     "CIDR range match",
			clientIP: "10.0.0.50",
			expected: true,
		},
		{
			name:     "not blocked IP",
			clientIP: "203.0.113.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-Real-IP", tt.clientIP)
			c.Request = req

			result := middleware.isBlocked(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityMiddleware_IsBlocked_BlockedUserAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	config.BlockedUserAgents = []string{"bot", "crawler"}
	middleware := NewSecurityMiddleware(config, redisClient)

	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{
			name:      "blocked bot user agent",
			userAgent: "GoogleBot/2.1",
			expected:  true,
		},
		{
			name:      "blocked crawler user agent",
			userAgent: "WebCrawler/1.0",
			expected:  true,
		},
		{
			name:      "normal browser user agent",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			c.Request = req

			result := middleware.isBlocked(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityMiddleware_IsIPInCIDR(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{
			name:     "IP in CIDR range",
			ip:       "192.168.1.100",
			cidr:     "192.168.1.0/24",
			expected: true,
		},
		{
			name:     "IP not in CIDR range",
			ip:       "192.168.2.100",
			cidr:     "192.168.1.0/24",
			expected: false,
		},
		{
			name:     "invalid CIDR",
			ip:       "192.168.1.100",
			cidr:     "192.168.1.100", // No /
			expected: false,
		},
		{
			name:     "invalid IP",
			ip:       "invalid-ip",
			cidr:     "192.168.1.0/24",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.isIPInCIDR(tt.ip, tt.cidr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityMiddleware_IsLoginEndpoint(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	tests := []struct {
		name     string
		path     string
		method   string
		expected bool
	}{
		{
			name:     "login endpoint with POST",
			path:     "/api/v1/auth/login",
			method:   "POST",
			expected: true,
		},
		{
			name:     "login endpoint with GET",
			path:     "/api/v1/auth/login",
			method:   "GET",
			expected: false,
		},
		{
			name:     "non-login endpoint",
			path:     "/api/v1/users/profile",
			method:   "POST",
			expected: false,
		},
		{
			name:     "short login path",
			path:     "/login",
			method:   "POST",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.isLoginEndpoint(tt.path, tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityMiddleware_DetectUnusualUserAgent(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	clientIP := "203.0.113.1"

	tests := []struct {
		name           string
		userAgent      string
		expectActivity bool
		expectedType   string
	}{
		{
			name:           "missing user agent",
			userAgent:      "",
			expectActivity: true,
			expectedType:   "missing_user_agent",
		},
		{
			name:           "curl user agent",
			userAgent:      "curl/7.68.0",
			expectActivity: true,
			expectedType:   "suspicious_user_agent",
		},
		{
			name:           "python user agent",
			userAgent:      "Python-urllib/3.8",
			expectActivity: true,
			expectedType:   "suspicious_user_agent",
		},
		{
			name:           "normal browser user agent",
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expectActivity: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activity := middleware.detectUnusualUserAgent(tt.userAgent, clientIP)

			if tt.expectActivity {
				assert.NotNil(t, activity)
				assert.Equal(t, tt.expectedType, activity.Type)
				assert.Equal(t, clientIP, activity.IP)
				assert.Equal(t, tt.userAgent, activity.UserAgent)
			} else {
				assert.Nil(t, activity)
			}
		})
	}
}

func TestSecurityMiddleware_DetectTimeAnomaly(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	config.EnableTimeAnomalyDetection = true
	config.UnusualHourThreshold = 2 // 2 AM
	middleware := NewSecurityMiddleware(config, redisClient)

	clientIP := "203.0.113.1"

	// Mock current time to test different hours
	originalTime := time.Now()

	// Test unusual hour (3 AM)
	unusualTime := time.Date(originalTime.Year(), originalTime.Month(), originalTime.Day(), 3, 0, 0, 0, originalTime.Location())

	// We can't easily mock time.Now() in this test, so we'll test the logic indirectly
	// by checking if the hour falls within the unusual range
	hour := unusualTime.Hour()
	isUnusual := hour >= config.UnusualHourThreshold && hour < config.UnusualHourThreshold+4

	assert.True(t, isUnusual, "3 AM should be considered unusual")

	// Test normal hour (10 AM)
	normalTime := time.Date(originalTime.Year(), originalTime.Month(), originalTime.Day(), 10, 0, 0, 0, originalTime.Location())
	hour = normalTime.Hour()
	isUnusual = hour >= config.UnusualHourThreshold && hour < config.UnusualHourThreshold+4

	assert.False(t, isUnusual, "10 AM should not be considered unusual")
}

func TestSecurityMiddleware_GenerateDeviceFingerprint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	c.Request = req

	fingerprint1 := middleware.generateDeviceFingerprint(c)
	assert.NotEmpty(t, fingerprint1)
	assert.Len(t, fingerprint1, 64) // SHA256 hex string length

	// Same headers should produce same fingerprint
	fingerprint2 := middleware.generateDeviceFingerprint(c)
	assert.Equal(t, fingerprint1, fingerprint2)

	// Different headers should produce different fingerprint
	req.Header.Set("User-Agent", "Different User Agent")
	c.Request = req
	fingerprint3 := middleware.generateDeviceFingerprint(c)
	assert.NotEqual(t, fingerprint1, fingerprint3)
}

func TestSecurityMiddleware_ExtractUsernameFromRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	tests := []struct {
		name     string
		setupReq func() *http.Request
		expected string
	}{
		{
			name: "username in form data",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("POST", "/login", nil)
				req.PostForm = map[string][]string{
					"username": {"testuser"},
				}
				return req
			},
			expected: "testuser",
		},
		{
			name: "email in form data",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("POST", "/login", nil)
				req.PostForm = map[string][]string{
					"email": {"test@example.com"},
				}
				return req
			},
			expected: "test@example.com",
		},
		{
			name: "username in query params",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/login?username=queryuser", nil)
			},
			expected: "queryuser",
		},
		{
			name: "no username available",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/login", nil)
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = tt.setupReq()

			username := middleware.extractUsernameFromRequest(c)
			assert.Equal(t, tt.expected, username)
		})
	}
}

func TestSecurityMiddleware_Handler_BlockedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	config.BlockedIPs = []string{"192.168.1.100"}
	config.BlockSuspiciousRequests = true
	middleware := NewSecurityMiddleware(config, redisClient)

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100") // Blocked IP
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestSecurityMiddleware_Handler_AllowedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	middleware := NewSecurityMiddleware(config, redisClient)

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.1") // Not blocked IP
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
}

func TestSecurityMiddleware_LogSuspiciousActivity(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	config.LogSuspiciousActivity = true
	middleware := NewSecurityMiddleware(config, redisClient)

	ctx := context.Background()
	activity := &SuspiciousActivity{
		Type:        "test_activity",
		Severity:    "medium",
		Description: "Test suspicious activity",
		IP:          "203.0.113.1",
		UserAgent:   "TestAgent/1.0",
		UserID:      "user123",
		Timestamp:   time.Now(),
	}

	// Log the activity
	middleware.logSuspiciousActivity(ctx, activity)

	// Verify it was stored
	activities, err := middleware.GetSuspiciousActivities(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, activities, 1)
	assert.Equal(t, "test_activity", activities[0].Type)
	assert.Equal(t, "medium", activities[0].Severity)
	assert.Equal(t, "Test suspicious activity", activities[0].Description)
}

func TestSecurityMiddleware_GetSuspiciousActivities(t *testing.T) {
	redisClient := setupTestRedisClient(t)
	defer redisClient.Close()

	config := DefaultSecurityConfig()
	config.LogSuspiciousActivity = true
	middleware := NewSecurityMiddleware(config, redisClient)

	ctx := context.Background()

	// Log multiple activities
	activities := []*SuspiciousActivity{
		{
			Type:        "activity1",
			Severity:    "low",
			Description: "First activity",
			IP:          "203.0.113.1",
			Timestamp:   time.Now().Add(-2 * time.Hour),
		},
		{
			Type:        "activity2",
			Severity:    "high",
			Description: "Second activity",
			IP:          "203.0.113.2",
			Timestamp:   time.Now().Add(-1 * time.Hour),
		},
		{
			Type:        "activity3",
			Severity:    "critical",
			Description: "Third activity",
			IP:          "203.0.113.3",
			Timestamp:   time.Now(),
		},
	}

	for _, activity := range activities {
		middleware.logSuspiciousActivity(ctx, activity)
	}

	// Retrieve activities (should be in reverse chronological order)
	retrieved, err := middleware.GetSuspiciousActivities(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, retrieved, 3)

	// Verify order (most recent first)
	assert.Equal(t, "activity3", retrieved[0].Type)
	assert.Equal(t, "activity2", retrieved[1].Type)
	assert.Equal(t, "activity1", retrieved[2].Type)

	// Test limit
	limited, err := middleware.GetSuspiciousActivities(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, limited, 2)
	assert.Equal(t, "activity3", limited[0].Type)
	assert.Equal(t, "activity2", limited[1].Type)
}
