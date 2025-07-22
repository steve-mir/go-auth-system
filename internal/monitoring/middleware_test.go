package monitoring

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestService_HTTPMiddleware(t *testing.T) {
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

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(service.HTTPMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestService_HTTPMiddleware_NilService(t *testing.T) {
	var service *Service

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(service.HTTPMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResponseWriterWrapper(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()

	wrapper := &responseWriterWrapper{
		ResponseWriter: w,
		size:           0,
	}

	// Test Write
	data := []byte("test data")
	n, err := wrapper.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, len(data), wrapper.size)

	// Test WriteString
	str := "test string"
	n, err = wrapper.WriteString(str)
	assert.NoError(t, err)
	assert.Equal(t, len(str), n)
	assert.Equal(t, len(data)+len(str), wrapper.size)
}

func TestService_GRPCUnaryInterceptor(t *testing.T) {
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

	interceptor := service.GRPCUnaryInterceptor()

	// Mock handler
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	// Mock info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.AuthService/Login",
	}

	ctx := context.Background()
	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
}

func TestService_GRPCUnaryInterceptor_WithError(t *testing.T) {
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

	interceptor := service.GRPCUnaryInterceptor()

	// Mock handler that returns error
	testErr := status.Error(codes.InvalidArgument, "invalid request")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, testErr
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.AuthService/Login",
	}

	ctx := context.Background()
	resp, err := interceptor(ctx, "request", info, handler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, testErr, err)
}

func TestService_GRPCUnaryInterceptor_NilService(t *testing.T) {
	var service *Service
	interceptor := service.GRPCUnaryInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.AuthService/Login",
	}

	ctx := context.Background()
	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
}

func TestService_GRPCStreamInterceptor(t *testing.T) {
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

	interceptor := service.GRPCStreamInterceptor()

	// Mock stream
	stream := &mockServerStream{
		ctx: context.Background(),
	}

	// Mock handler
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/auth.AuthService/StreamMethod",
	}

	err = interceptor(nil, stream, info, handler)
	assert.NoError(t, err)
}

func TestService_DatabaseMiddleware(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelDebug,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	middleware := service.DatabaseMiddleware()

	// Test successful operation
	err = middleware("SELECT", "users", func() error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)

	// Test failed operation
	testErr := errors.New("database error")
	err = middleware("INSERT", "users", func() error {
		return testErr
	})
	assert.Equal(t, testErr, err)
}

func TestService_CacheMiddleware(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelDebug,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	middleware := service.CacheMiddleware()
	ctx := context.Background()

	// Test cache hit
	hit, err := middleware(ctx, "redis", "get", "user:123", func() (bool, error) {
		return true, nil
	})
	assert.NoError(t, err)
	assert.True(t, hit)

	// Test cache miss
	hit, err = middleware(ctx, "redis", "get", "user:456", func() (bool, error) {
		return false, nil
	})
	assert.NoError(t, err)
	assert.False(t, hit)

	// Test cache error
	testErr := errors.New("cache error")
	hit, err = middleware(ctx, "redis", "set", "user:789", func() (bool, error) {
		return false, testErr
	})
	assert.Equal(t, testErr, err)
	assert.False(t, hit)
}

func TestService_AuthMiddleware(t *testing.T) {
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

	middleware := service.AuthMiddleware()
	ctx := context.Background()

	// Test successful auth
	err = middleware(ctx, "password", "user123", func() error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)

	// Test failed auth
	testErr := errors.New("invalid password")
	err = middleware(ctx, "password", "user123", func() error {
		return testErr
	})
	assert.Equal(t, testErr, err)
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users", "/api/users"},
		{"/api/users?page=1", "/api/users"},
		{"/api/users?page=1&limit=10", "/api/users"},
		{"/api/users/123", "/api/users/123"}, // Simple implementation doesn't handle this
		{"/health", "/health"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeEndpoint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseGRPCMethod(t *testing.T) {
	tests := []struct {
		fullMethod      string
		expectedService string
		expectedMethod  string
	}{
		{"/auth.AuthService/Login", "AuthService", "Login"},
		{"/user.UserService/GetProfile", "UserService", "GetProfile"},
		{"/package.subpackage.Service/Method", "Service", "Method"},
		{"invalid", "", ""},
		{"/Service/Method", "Service", "Method"},
	}

	for _, tt := range tests {
		t.Run(tt.fullMethod, func(t *testing.T) {
			service, method := parseGRPCMethod(tt.fullMethod)
			assert.Equal(t, tt.expectedService, service)
			assert.Equal(t, tt.expectedMethod, method)
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "no peer info",
			ctx:      context.Background(),
			expected: "unknown",
		},
		{
			name: "with x-forwarded-for",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-forwarded-for", "192.168.1.1"),
			),
			expected: "192.168.1.1",
		},
		{
			name: "with x-real-ip",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-real-ip", "10.0.0.1"),
			),
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getClientIP(tt.ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCategorizeAuthError(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{nil, ""},
		{errors.New("invalid password"), "invalid_password"},
		{errors.New("user not found"), "user_not_found"},
		{errors.New("invalid token"), "invalid_token"},
		{errors.New("token expired"), "expired_credentials"},
		{errors.New("account locked"), "account_locked"},
		{errors.New("account disabled"), "account_disabled"},
		{errors.New("rate limit exceeded"), "rate_limited"},
		{errors.New("mfa required"), "mfa_required"},
		{errors.New("unknown error"), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := categorizeAuthError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHealthCheckMiddleware(t *testing.T) {
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

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(service.HealthCheckMiddleware())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.GET("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	// Test health endpoint (should skip monitoring)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test regular endpoint (should include monitoring)
	req = httptest.NewRequest("GET", "/api/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestIDMiddleware())

	router.GET("/test", func(c *gin.Context) {
		requestID := c.Request.Context().Value("request_id")
		assert.NotNil(t, requestID)
		c.JSON(http.StatusOK, gin.H{"request_id": requestID})
	})

	// Test without existing request ID
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

	// Test with existing request ID
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "existing-id")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "existing-id", w.Header().Get("X-Request-ID"))
}

func TestTraceIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(TraceIDMiddleware())

	router.GET("/test", func(c *gin.Context) {
		traceID := c.Request.Context().Value("trace_id")
		assert.NotNil(t, traceID)
		c.JSON(http.StatusOK, gin.H{"trace_id": traceID})
	})

	// Test without existing trace ID
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Trace-ID"))

	// Test with existing trace ID
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Trace-ID", "existing-trace")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "existing-trace", w.Header().Get("X-Trace-ID"))
}

// Mock implementations for testing

type mockServerStream struct {
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SetTrailer(metadata.MD) {
}
